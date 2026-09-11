//! CLI coordination for explicit compiler/project semantic contexts.
//!
//! Native analysis remains the default.  When a project option is present this
//! module loads each owner context once from the exact source snapshots retained
//! by `analyze`; incomplete contexts stay diagnostic and never become a
//! successful zero-finding semantic result.  Fix verification uses the same
//! configuration and source inventory, rebuilding the owner context whenever a
//! projected in-memory source differs from the original snapshot.

use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use hoonarqube_core::Language;
use hoonarqube_ir::FileReport;
use sha2::{Digest as _, Sha256};

use crate::analyze::{AnalyzerOptionsBundle, MAX_RETAINED_SOURCE_BYTES};
use crate::cache::CacheFingerprints;
use crate::project_features::{AnalyzedSource, SemanticOptions};

/// Contexts loaded for one complete project source inventory.
#[derive(Debug)]
pub(crate) struct ProjectSemanticContext {
    jsts: Option<hoonarqube_jsts::project_context::ProjectSemanticContext>,
    csharp: Option<hoonarqube_csharp::semantic::ProjectSemanticContext>,
    python: Option<hoonarqube_python::PythonProjectContext>,
    complete: bool,
    diagnostics: Vec<String>,
    fingerprints: CacheFingerprints,
}

impl ProjectSemanticContext {
    /// Loads all explicitly requested semantic contexts once.
    ///
    /// The only hard error is an unsupported profile combination.  Missing
    /// files, runtimes, helpers, references, compiler diagnostics, and
    /// incomplete owner contexts are retained as diagnostics and make this
    /// context incomplete.
    pub(crate) fn load(
        sources: &[AnalyzedSource],
        semantic: &SemanticOptions,
        options: &AnalyzerOptionsBundle,
    ) -> Result<Self, String> {
        let context_sources = load_csharp_context_sources(semantic);
        Self::load_with_context_sources(
            sources,
            &context_sources.snapshots,
            &context_sources.diagnostics,
            semantic,
            options,
        )
    }

    /// Loads semantic contexts from the analyzed snapshots plus immutable
    /// auxiliary C# snapshots.  Auxiliary snapshots never become analyzed
    /// files, project roots, metrics, or fix inventory.
    pub(crate) fn load_with_context_sources(
        sources: &[AnalyzedSource],
        context_sources: &[AnalyzedSource],
        context_diagnostics: &[String],
        semantic: &SemanticOptions,
        options: &AnalyzerOptionsBundle,
    ) -> Result<Self, String> {
        if !semantic.requested() {
            return Ok(Self {
                jsts: None,
                csharp: None,
                python: None,
                complete: true,
                diagnostics: Vec::new(),
                fingerprints: CacheFingerprints::default(),
            });
        }
        if options.profile == hoonarqube_catalog::RuleProfile::GithubCodeQuality {
            return Err(
                "compiler-backed semantic contexts are not supported with the isolated github-code-quality profile"
                    .to_owned(),
            );
        }

        let mut diagnostics = context_diagnostics.to_vec();
        let mut fingerprints = SemanticFingerprintParts::default();
        let jsts = load_jsts_context(sources, semantic, &mut diagnostics, &mut fingerprints);
        let csharp = load_csharp_context(
            sources,
            context_sources,
            semantic,
            &mut diagnostics,
            &mut fingerprints,
        );
        let python = load_python_context(sources, semantic, &mut diagnostics, &mut fingerprints);
        let complete = semantic_context_complete(
            semantic,
            jsts.as_ref(),
            csharp.as_ref(),
            python.as_ref(),
            &diagnostics,
        );
        Ok(Self {
            jsts,
            csharp,
            python,
            complete,
            diagnostics,
            fingerprints: semantic_cache_fingerprints(&fingerprints),
        })
    }

    #[must_use]
    pub(crate) const fn is_complete(&self) -> bool {
        self.complete
    }

    #[must_use]
    pub(crate) fn diagnostics(&self) -> &[String] {
        &self.diagnostics
    }

    #[must_use]
    pub(crate) fn cache_fingerprints(&self) -> &CacheFingerprints {
        &self.fingerprints
    }

    /// Returns complete compiler-backed Razor facts for an exact source
    /// snapshot, when the loaded C# context owns them.
    #[must_use]
    pub(crate) fn razor_source_facts(
        &self,
        path: &Path,
        source: &str,
    ) -> Option<&hoonarqube_csharp::semantic::RazorSourceFacts> {
        self.csharp
            .as_ref()
            .and_then(|context| context.razor_source_facts(path, source))
    }

    /// Analyzes one current source through the applicable loaded owner context.
    /// `None` means no requested context applies to this language.
    pub(crate) fn analyze(
        &self,
        path: &Path,
        source: &str,
        options: &AnalyzerOptionsBundle,
    ) -> Result<Option<FileReport>, String> {
        let language = hoonarqube_core::language_for_path(path);
        match language {
            Some(Language::JavaScript | Language::TypeScript) => {
                let Some(context) = self.jsts.as_ref() else {
                    return Ok(None);
                };
                if !context.is_complete() {
                    return Ok(None);
                }
                let language = if language == Some(Language::JavaScript) {
                    hoonarqube_jsts::JstsLanguage::JavaScript
                } else {
                    hoonarqube_jsts::JstsLanguage::TypeScript
                };
                let result = context.analyze_with_context(
                    path.to_path_buf(),
                    source,
                    language,
                    &options.jsts,
                );
                if let Some(diagnostic) = result
                    .diagnostics
                    .iter()
                    .find(|diagnostic| diagnostic.category == "error")
                {
                    return Err(format!("{}: {}", diagnostic.code, diagnostic.message));
                }
                Ok(Some(result.report))
            }
            Some(Language::CSharp) => {
                let Some(context) = self.csharp.as_ref() else {
                    return Ok(None);
                };
                if !context.is_complete() {
                    return Ok(None);
                }
                Ok(Some(context.analyze_with_context(
                    path.to_path_buf(),
                    source,
                    hoonarqube_csharp::CsLanguage::CSharp,
                    &options.csharp,
                )))
            }
            Some(Language::Python) => {
                let Some(context) = self.python.as_ref() else {
                    return Ok(None);
                };
                Ok(Some(hoonarqube_python::analyze_with_context(
                    path.to_path_buf(),
                    source,
                    &options.python,
                    context,
                )))
            }
            _ => Ok(None),
        }
    }
}
#[derive(Default)]
struct SemanticFingerprintParts {
    context: Vec<String>,
    helper: Vec<String>,
    config: Vec<String>,
    reference: Vec<String>,
    dependency: Vec<String>,
}
#[derive(Default)]
struct ContextSourceLoad {
    snapshots: Vec<AnalyzedSource>,
    diagnostics: Vec<String>,
}

/// Loads only explicitly named auxiliary C# snapshots.  These files are kept
/// outside the analyzed inventory and are bounded by the same retained-source
/// limit as positional project inputs.
fn load_csharp_context_sources(semantic: &SemanticOptions) -> ContextSourceLoad {
    let mut loaded = ContextSourceLoad::default();
    if semantic.csharp_context_sources.is_empty()
        || semantic
            .csharp_project
            .as_ref()
            .is_none_or(|project| !project.exists())
    {
        return loaded;
    }

    let mut identities = std::collections::BTreeSet::new();
    let mut retained_bytes = 0usize;
    for path in &semantic.csharp_context_sources {
        if hoonarqube_core::language_for_path(path) != Some(Language::CSharp) {
            loaded.diagnostics.push(format!(
                "csharp context source is not a C# source file: {}",
                path.display()
            ));
            continue;
        }
        if !identities.insert(snapshot_identity_path(path)) {
            continue;
        }
        let remaining = MAX_RETAINED_SOURCE_BYTES - retained_bytes;
        let source = match read_csharp_context_source(path, remaining) {
            Ok(source) => source,
            Err(reason) => {
                loaded.diagnostics.push(format!(
                    "cannot read csharp context source {}: {reason}",
                    path.display()
                ));
                continue;
            }
        };
        retained_bytes += source.len();
        loaded.snapshots.push(AnalyzedSource {
            path: path.clone(),
            source,
            classification: hoonarqube_ir::FileClassification::Source,
        });
    }

    loaded
}

fn read_csharp_context_source(path: &Path, remaining: usize) -> Result<String, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if !metadata.is_file() {
        return Err("source is not a regular file".to_owned());
    }
    let limit = u64::try_from(remaining).map_err(|error| error.to_string())?;
    if metadata.len() > limit {
        return Err(format!(
            "source exceeds the {remaining} byte remaining context snapshot budget"
        ));
    }
    let file = fs::File::open(path).map_err(|error| error.to_string())?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() > remaining {
        return Err(format!(
            "source exceeds the {remaining} byte remaining context snapshot budget"
        ));
    }
    String::from_utf8(bytes).map_err(|_| "source is not valid UTF-8".to_owned())
}

fn snapshot_identity_path(path: &Path) -> PathBuf {
    absolute_lexical(path)
}

fn load_jsts_context(
    sources: &[AnalyzedSource],
    semantic: &SemanticOptions,
    diagnostics: &mut Vec<String>,
    fingerprints: &mut SemanticFingerprintParts,
) -> Option<hoonarqube_jsts::project_context::ProjectSemanticContext> {
    let Some(project) = semantic.typescript_project.as_ref() else {
        if semantic.typescript_module.is_some() {
            diagnostics.push(
                "typescript project configuration is required when --typescript-module is supplied"
                    .to_owned(),
            );
        }
        if !semantic.typescript_dependency_whitelist.is_empty() {
            diagnostics.push(
                "typescript project configuration is required when --typescript-dependency-whitelist is supplied"
                    .to_owned(),
            );
        }
        return None;
    };
    let config = match typescript_config(
        project,
        semantic.typescript_module.as_deref(),
        &semantic.typescript_dependency_whitelist,
    ) {
        Ok(config) => config,
        Err(error) => {
            diagnostics.push(error);
            return None;
        }
    };
    let pairs = sources
        .iter()
        .filter(|source| {
            matches!(
                hoonarqube_core::language_for_path(&source.path),
                Some(Language::JavaScript | Language::TypeScript)
            )
        })
        .map(|source| (source.path.clone(), source.source.clone()));
    let semantic_sources =
        hoonarqube_jsts::project_context::ProjectSemanticSources::from_pairs(pairs);
    match hoonarqube_jsts::project_context::ProjectSemanticContext::load(&config, &semantic_sources)
    {
        Ok(context) => {
            record_jsts_context(&config, &context, diagnostics, fingerprints);
            Some(context)
        }
        Err(error) => {
            diagnostics.push(format!("{}: {}", error.code, error.message));
            diagnostics.extend(
                error
                    .diagnostics
                    .into_iter()
                    .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message)),
            );
            None
        }
    }
}

fn record_jsts_context(
    config: &hoonarqube_jsts::project_context::TypeScriptProjectConfig,
    context: &hoonarqube_jsts::project_context::ProjectSemanticContext,
    diagnostics: &mut Vec<String>,
    fingerprints: &mut SemanticFingerprintParts,
) {
    diagnostics.extend(jsts_diagnostics(context));
    if !context.is_complete() && context.diagnostics().is_empty() {
        diagnostics.push(
            "typescript semantic context is incomplete; compiler facts are unavailable".to_owned(),
        );
    }
    fingerprints.context.push(context.fingerprint().to_owned());
    fingerprints.helper.push(digest_values(
        "typescript-helper-v1",
        &[
            config.helper_program.as_os_str().as_encoded_bytes(),
            config
                .helper_script
                .as_deref()
                .map_or(&[][..], |path| path.as_os_str().as_encoded_bytes()),
            context.compiler_version().unwrap_or_default().as_bytes(),
            context
                .compiler_path()
                .map_or(&[][..], |path| path.as_os_str().as_encoded_bytes()),
        ],
    ));
    fingerprints
        .config
        .push(typescript_config_fingerprint(config));
    let mut dependency_values = Vec::new();
    for dependency in context.dependencies() {
        dependency_values.push(dependency.path.as_os_str().as_encoded_bytes());
        dependency_values.push(dependency.digest.as_bytes());
        dependency_values.push(dependency.kind.as_deref().unwrap_or_default().as_bytes());
    }
    fingerprints.dependency.push(digest_values(
        "typescript-dependencies-v1",
        &dependency_values,
    ));
}

fn load_csharp_context(
    sources: &[AnalyzedSource],
    context_sources: &[AnalyzedSource],
    semantic: &SemanticOptions,
    diagnostics: &mut Vec<String>,
    fingerprints: &mut SemanticFingerprintParts,
) -> Option<hoonarqube_csharp::semantic::ProjectSemanticContext> {
    let Some(project) = semantic.csharp_project.as_ref() else {
        if semantic.csharp_context_sources.is_empty() {
            // Keep the existing diagnostics for the other C#-specific knobs.
        } else {
            diagnostics.push(
                "csharp project configuration is required when --csharp-context-source is supplied"
                    .to_owned(),
            );
        }
        if semantic.csharp_timeout_ms.is_some() {
            diagnostics.push(
                "csharp project configuration is required when --csharp-timeout-ms is supplied"
                    .to_owned(),
            );
        }
        if semantic.csharp_s110_max.is_some() {
            diagnostics.push(
                "csharp project configuration is required when --csharp-s110-max is supplied"
                    .to_owned(),
            );
        }
        if !semantic.csharp_s110_filtered_class.is_empty() {
            diagnostics.push(
                "csharp project configuration is required when --csharp-s110-filtered-class is supplied"
                    .to_owned(),
            );
        }
        if semantic.csharp_s1200_max.is_some() {
            diagnostics.push(
                "csharp project configuration is required when --csharp-s1200-max is supplied"
                    .to_owned(),
            );
        }
        return None;
    };
    if !project.exists() {
        diagnostics.push(format!(
            "csharp project does not exist: {}",
            project.display()
        ));
        return None;
    }
    let mut config = hoonarqube_csharp::semantic::ProjectSemanticConfig::default();
    if let Some(timeout_ms) = semantic.csharp_timeout_ms {
        if timeout_ms == 0 {
            diagnostics.push("csharp timeout must be a positive finite integer".to_owned());
            return None;
        }
        config.timeout_ms = timeout_ms;
    }
    apply_csharp_rule_options(&mut config, semantic);
    config.project.clone_from(project);
    // A single explicit CLI trust flag gates both evaluation and
    // any build/Razor generation.  The owner loader checks this
    // before looking for or invoking a helper.
    config.trusted_evaluation = semantic.allow_project_build;
    config.trusted_build = semantic.allow_project_build;

    let snapshots = merged_csharp_snapshots(sources, context_sources, diagnostics);
    config.include_razor_generated = semantic.allow_project_build
        && snapshots
            .iter()
            .any(|source| hoonarqube_core::is_razor_path(&source.path));
    record_context_source_fingerprints(context_sources, fingerprints);
    let context = hoonarqube_csharp::semantic::ProjectSemanticContext::load(&config, &snapshots);
    record_csharp_context(&config, &context, diagnostics, fingerprints);
    Some(context)
}

fn merged_csharp_snapshots(
    sources: &[AnalyzedSource],
    context_sources: &[AnalyzedSource],
    diagnostics: &mut Vec<String>,
) -> Vec<hoonarqube_csharp::semantic::SourceSnapshot> {
    let mut identities = std::collections::BTreeMap::<PathBuf, usize>::new();
    let mut merged = Vec::<(PathBuf, String)>::new();
    for source in sources {
        insert_csharp_snapshot(
            &mut identities,
            &mut merged,
            source,
            "analyzed",
            diagnostics,
        );
    }
    for source in context_sources {
        insert_csharp_snapshot(&mut identities, &mut merged, source, "context", diagnostics);
    }
    let snapshots = merged
        .into_iter()
        .map(|(path, source)| hoonarqube_csharp::semantic::SourceSnapshot::new(path, source))
        .collect::<Vec<_>>();
    let retained_bytes = snapshots.iter().try_fold(0usize, |total, snapshot| {
        total.checked_add(snapshot.source.len())
    });
    if retained_bytes.is_none_or(|total| total > MAX_RETAINED_SOURCE_BYTES) {
        diagnostics.push(format!(
            "csharp semantic source snapshots exceed the {MAX_RETAINED_SOURCE_BYTES} byte project limit"
        ));
        return Vec::new();
    }
    snapshots
}

fn insert_csharp_snapshot(
    identities: &mut std::collections::BTreeMap<PathBuf, usize>,
    merged: &mut Vec<(PathBuf, String)>,
    source: &AnalyzedSource,
    origin: &str,
    diagnostics: &mut Vec<String>,
) {
    if hoonarqube_core::language_for_path(&source.path) != Some(Language::CSharp) {
        if origin == "context" {
            diagnostics.push(format!(
                "csharp context source is not a C# source file: {}",
                source.path.display()
            ));
        }
        return;
    }
    let identity = snapshot_identity_path(&source.path);
    if let Some(index) = identities.get(&identity) {
        let (previous_path, previous_source) = &merged[*index];
        if previous_source != &source.source {
            diagnostics.push(format!(
                "csharp {origin} source overlaps {} with different content: {}",
                previous_path.display(),
                source.path.display()
            ));
        }
        return;
    }
    identities.insert(identity, merged.len());
    merged.push((source.path.clone(), source.source.clone()));
}

fn record_context_source_fingerprints(
    context_sources: &[AnalyzedSource],
    fingerprints: &mut SemanticFingerprintParts,
) {
    for source in context_sources {
        let identity = snapshot_identity_path(&source.path);
        fingerprints.context.push(digest_values(
            "csharp-context-source-v1",
            &[
                identity.as_os_str().as_encoded_bytes(),
                source.source.as_bytes(),
            ],
        ));
    }
}

fn record_csharp_context(
    config: &hoonarqube_csharp::semantic::ProjectSemanticConfig,
    context: &hoonarqube_csharp::semantic::ProjectSemanticContext,
    diagnostics: &mut Vec<String>,
    fingerprints: &mut SemanticFingerprintParts,
) {
    diagnostics.extend(
        context
            .diagnostics
            .iter()
            .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message)),
    );
    if !context.is_complete() && context.diagnostics.is_empty() {
        diagnostics.push(
            "csharp semantic context is incomplete; compiler facts are unavailable".to_owned(),
        );
    }
    fingerprints
        .context
        .push(context.context_fingerprint.clone());
    fingerprints.helper.push(digest_values(
        "csharp-helper-v1",
        &[
            config.helper.as_ref().map_or(&[][..], |helper| {
                helper.program.as_os_str().as_encoded_bytes()
            }),
            context.compiler.helper_version.as_bytes(),
            context.compiler.compiler_version.as_bytes(),
            context.compiler.sdk_version.as_bytes(),
        ],
    ));
    fingerprints.config.push(context.config_digest.clone());
    fingerprints
        .reference
        .push(context.compiler.reference_digest.clone());
    fingerprints
        .dependency
        .push(context.dependency_fingerprint.clone());
}

fn apply_csharp_rule_options(
    config: &mut hoonarqube_csharp::semantic::ProjectSemanticConfig,
    semantic: &SemanticOptions,
) {
    if let Some(max) = semantic.csharp_s110_max {
        config.rules.s110_max = max;
    }
    config
        .rules
        .s110_filtered_classes
        .clone_from(&semantic.csharp_s110_filtered_class);
    if let Some(max) = semantic.csharp_s1200_max {
        config.rules.s1200_max = max;
        config.rules.s1200_enabled = true;
    }
}

fn load_python_context(
    sources: &[AnalyzedSource],
    semantic: &SemanticOptions,
    diagnostics: &mut Vec<String>,
    fingerprints: &mut SemanticFingerprintParts,
) -> Option<hoonarqube_python::PythonProjectContext> {
    let project = semantic.python_project.as_ref()?;
    match fs::metadata(project) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            diagnostics.push(format!(
                "python project path does not exist: {}",
                project.display()
            ));
            return None;
        }
        Err(error) => {
            diagnostics.push(format!(
                "cannot inspect python project {}: {error}",
                project.display()
            ));
            return None;
        }
    }
    let root = project_root(project);
    if !root.is_dir() {
        diagnostics.push(format!(
            "python project directory does not exist: {}",
            root.display()
        ));
        return None;
    }
    let mut context = hoonarqube_python::PythonProjectContext::new();
    let root_absolute = absolute_lexical(&root);
    let mut fingerprint_parts = vec![digest_values(
        "python-root-v1",
        &[root_absolute.as_os_str().as_encoded_bytes()],
    )];
    for source in sources
        .iter()
        .filter(|source| hoonarqube_core::language_for_path(&source.path) == Some(Language::Python))
    {
        let source_absolute = absolute_lexical(&source.path);
        let module_path = source_absolute
            .strip_prefix(&root_absolute)
            .unwrap_or(source_absolute.as_path())
            .to_path_buf();
        context.add_path(module_path.clone(), &source.source);
        fingerprint_parts.push(digest_values(
            "python-source-v1",
            &[
                module_path.as_os_str().as_encoded_bytes(),
                source.source.as_bytes(),
            ],
        ));
    }
    let fingerprint_parts = fingerprint_parts
        .iter()
        .map(String::as_bytes)
        .collect::<Vec<_>>();
    let fingerprint = digest_values("python-project-v2", &fingerprint_parts);
    fingerprints.context.push(fingerprint.clone());
    fingerprints.config.push(digest_values(
        "python-config-v1",
        &[root_absolute.as_os_str().as_encoded_bytes()],
    ));
    fingerprints.dependency.push(fingerprint);
    Some(context)
}

fn semantic_context_complete(
    semantic: &SemanticOptions,
    jsts: Option<&hoonarqube_jsts::project_context::ProjectSemanticContext>,
    csharp: Option<&hoonarqube_csharp::semantic::ProjectSemanticContext>,
    python: Option<&hoonarqube_python::PythonProjectContext>,
    diagnostics: &[String],
) -> bool {
    (semantic.typescript_project.is_none() && semantic.typescript_module.is_none()
        || jsts.is_some_and(hoonarqube_jsts::project_context::ProjectSemanticContext::is_complete))
        && (semantic.csharp_project.is_none()
            || csharp.is_some_and(hoonarqube_csharp::semantic::ProjectSemanticContext::is_complete))
        && (semantic.python_project.is_none() || python.is_some())
        && diagnostics.is_empty()
}

fn semantic_cache_fingerprints(parts: &SemanticFingerprintParts) -> CacheFingerprints {
    CacheFingerprints {
        context: digest_values(
            "semantic-context-v1",
            &parts
                .context
                .iter()
                .map(String::as_bytes)
                .collect::<Vec<_>>(),
        ),
        helper: digest_values(
            "semantic-helper-v1",
            &parts
                .helper
                .iter()
                .map(String::as_bytes)
                .collect::<Vec<_>>(),
        ),
        config: digest_values(
            "semantic-config-v1",
            &parts
                .config
                .iter()
                .map(String::as_bytes)
                .collect::<Vec<_>>(),
        ),
        reference: digest_values(
            "semantic-reference-v1",
            &parts
                .reference
                .iter()
                .map(String::as_bytes)
                .collect::<Vec<_>>(),
        ),
        dependency: digest_values(
            "semantic-dependency-v1",
            &parts
                .dependency
                .iter()
                .map(String::as_bytes)
                .collect::<Vec<_>>(),
        ),
    }
}

/// Semantic context used by fix planning and post-edit verification.
#[derive(Debug)]
pub(crate) struct FixAnalysisContext {
    options: AnalyzerOptionsBundle,
    semantic: SemanticOptions,
    sources: Vec<AnalyzedSource>,
    context_sources: Vec<AnalyzedSource>,
    base: ProjectSemanticContext,
}

impl FixAnalysisContext {
    /// Reads the fix inventory once and validates one complete base context.
    pub(crate) fn load(
        paths: &[PathBuf],
        semantic: &SemanticOptions,
        options: &AnalyzerOptionsBundle,
    ) -> Result<Self, String> {
        if !semantic.requested() {
            return Ok(Self {
                options: options.clone(),
                semantic: semantic.clone(),
                sources: Vec::new(),
                context_sources: Vec::new(),
                base: ProjectSemanticContext::load(&[], semantic, options)?,
            });
        }
        let mut warnings = Vec::new();
        let files = crate::analyze::collect_input_files(paths, &mut warnings);
        if !warnings.is_empty() {
            return Err(warnings.join("; "));
        }
        let mut sources = Vec::with_capacity(files.len());
        let mut retained_bytes = 0usize;
        for path in files {
            let source = fs::read_to_string(&path).map_err(|error| {
                format!(
                    "cannot read semantic fix source {}: {error}",
                    path.display()
                )
            })?;
            retained_bytes = retained_bytes
                .checked_add(source.len())
                .ok_or_else(|| "semantic fix source snapshot size overflowed".to_owned())?;
            if retained_bytes > MAX_RETAINED_SOURCE_BYTES {
                return Err(format!(
                    "semantic fix source snapshots exceed the {MAX_RETAINED_SOURCE_BYTES} byte project limit"
                ));
            }
            sources.push(AnalyzedSource {
                path,
                source,
                classification: hoonarqube_ir::FileClassification::Source,
            });
        }
        let context_source_load = load_csharp_context_sources(semantic);
        if !context_source_load.diagnostics.is_empty() {
            return Err(context_source_load.diagnostics.join("; "));
        }
        let base = ProjectSemanticContext::load_with_context_sources(
            &sources,
            &context_source_load.snapshots,
            &[],
            semantic,
            options,
        )?;
        if !base.is_complete() {
            return Err(format_diagnostics(base.diagnostics()));
        }
        Ok(Self {
            options: options.clone(),
            semantic: semantic.clone(),
            sources,
            context_sources: context_source_load.snapshots,
            base,
        })
    }

    /// Analyzes one source.  A projected source rebuilds the compiler context
    /// with the projected snapshot and all unchanged project sources.
    pub(crate) fn analyze(&self, path: &Path, source: &str) -> Result<Option<FileReport>, String> {
        if hoonarqube_core::is_razor_path(path) && !self.semantic.requested() {
            return Err(
                "Razor analysis requires a complete trusted C# compiler context".to_owned(),
            );
        }
        if !self.semantic.requested() {
            return Ok(hoonarqube_core::analyze(path, source, &self.options));
        }
        let same_as_base = self
            .sources
            .iter()
            .find(|item| same_path(&item.path, path))
            .is_some_and(|item| item.source == source);
        if same_as_base {
            return self.analyze_context(&self.base, path, source);
        }
        let mut projected = self.sources.clone();
        let Some(item) = projected
            .iter_mut()
            .find(|item| same_path(&item.path, path))
        else {
            return Err(format!(
                "semantic fix source was not part of the immutable project inventory: {}",
                path.display()
            ));
        };
        item.source.clear();
        item.source.push_str(source);
        // An analyzed file is authoritative during a projected fix.  If the
        // same path was also supplied as context, discard its frozen base
        // snapshot rather than sending stale bytes beside the edit.  Context-
        // exclusive files remain immutable for the verification rebuild.
        let projected_identity = snapshot_identity_path(path);
        let projected_context_sources = self
            .context_sources
            .iter()
            .filter(|item| snapshot_identity_path(&item.path) != projected_identity)
            .cloned()
            .collect::<Vec<_>>();
        let context = ProjectSemanticContext::load_with_context_sources(
            &projected,
            &projected_context_sources,
            &[],
            &self.semantic,
            &self.options,
        )?;
        if !context.is_complete() {
            return Err(format_diagnostics(context.diagnostics()));
        }
        self.analyze_context(&context, path, source)
    }

    fn analyze_context(
        &self,
        context: &ProjectSemanticContext,
        path: &Path,
        source: &str,
    ) -> Result<Option<FileReport>, String> {
        let report = context.analyze(path, source, &self.options)?;
        if hoonarqube_core::is_razor_path(path)
            && context.razor_source_facts(path, source).is_none()
        {
            return Err("complete compiler-backed Razor source facts are unavailable".to_owned());
        }
        Ok(report)
    }
}

fn typescript_config(
    project: &Path,
    module: Option<&Path>,
    dependency_whitelist: &[String],
) -> Result<hoonarqube_jsts::project_context::TypeScriptProjectConfig, String> {
    if !project.exists() {
        return Err(format!(
            "typescript project does not exist: {}",
            project.display()
        ));
    }
    let (root, tsconfig) = if project.is_dir() {
        (project.to_path_buf(), project.join("tsconfig.json"))
    } else {
        let root = project
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        (root.to_path_buf(), project.to_path_buf())
    };
    if !tsconfig.is_file() {
        return Err(format!(
            "typescript project configuration does not exist: {}",
            tsconfig.display()
        ));
    }
    if let Some(module) = module
        && !module.exists()
    {
        return Err(format!(
            "typescript compiler module does not exist: {}",
            module.display()
        ));
    }
    let mut config = hoonarqube_jsts::project_context::TypeScriptProjectConfig::new(root);
    config.tsconfig = Some(tsconfig);
    if let Some(module) = module {
        config = config.with_typescript_package(module);
    }
    config = config.with_dependency_whitelist(dependency_whitelist.to_vec());
    Ok(config)
}

fn typescript_config_fingerprint(
    config: &hoonarqube_jsts::project_context::TypeScriptProjectConfig,
) -> String {
    let tsconfig = config
        .tsconfig
        .as_ref()
        .and_then(|path| fs::read(path).ok())
        .unwrap_or_default();
    let max_output = config.max_output_bytes.to_le_bytes();
    let mut values = vec![
        config.root.as_os_str().as_encoded_bytes(),
        config
            .tsconfig
            .as_deref()
            .map_or(&[][..], |path| path.as_os_str().as_encoded_bytes()),
        &tsconfig,
        config
            .typescript_package
            .as_deref()
            .map_or(&[][..], |path| path.as_os_str().as_encoded_bytes()),
        config.helper_program.as_os_str().as_encoded_bytes(),
        config.expected_compiler_version.as_bytes(),
        &max_output,
    ];
    for argument in &config.helper_args {
        values.push(argument.as_encoded_bytes());
    }
    for package in &config.dependency_whitelist {
        values.push(package.as_bytes());
    }
    digest_values("typescript-config-v1", &values)
}

fn project_root(path: &Path) -> PathBuf {
    if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
    }
}

fn jsts_diagnostics(
    context: &hoonarqube_jsts::project_context::ProjectSemanticContext,
) -> Vec<String> {
    context
        .diagnostics()
        .iter()
        .map(|diagnostic| format!("{}: {}", diagnostic.code, diagnostic.message))
        .collect()
}

fn format_diagnostics(diagnostics: &[String]) -> String {
    if diagnostics.is_empty() {
        "semantic project context is incomplete".to_owned()
    } else {
        diagnostics.join("; ")
    }
}

fn same_path(left: &Path, right: &Path) -> bool {
    absolute_lexical(left) == absolute_lexical(right)
}

fn absolute_lexical(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                normalized.push(component.as_os_str());
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                let _ = normalized.pop();
            }
            std::path::Component::Normal(value) => normalized.push(value),
        }
    }
    normalized
}

fn digest_values(domain: &str, values: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    let domain_len = u64::try_from(domain.len()).unwrap_or(u64::MAX);
    hasher.update(domain_len.to_le_bytes());
    hasher.update(domain.as_bytes());
    for value in values {
        hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(value);
    }
    let digest = hasher.finalize();
    let mut result = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csharp_context_source_reads_respect_remaining_byte_budget() {
        let path = std::env::temp_dir().join(format!(
            "hoonarqube-context-budget-{}-{}.cs",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::write(&path, "//é").unwrap();
        assert_eq!(read_csharp_context_source(&path, 4).unwrap(), "//é");
        assert!(read_csharp_context_source(&path, 3).is_err());
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(u64::try_from(MAX_RETAINED_SOURCE_BYTES).unwrap() + 1)
            .unwrap();
        assert!(read_csharp_context_source(&path, MAX_RETAINED_SOURCE_BYTES).is_err());
        drop(file);
        fs::remove_file(path).unwrap();
        assert!(read_csharp_context_source(&std::env::temp_dir(), 4).is_err());
    }

    fn source(path: &str, text: &str) -> AnalyzedSource {
        AnalyzedSource {
            path: PathBuf::from(path),
            source: text.to_owned(),
            classification: hoonarqube_ir::FileClassification::Source,
        }
    }

    #[test]
    fn csharp_context_sources_require_a_project() {
        let semantic = SemanticOptions {
            csharp_context_sources: vec![PathBuf::from("Context.cs")],
            ..SemanticOptions::default()
        };
        let context =
            ProjectSemanticContext::load(&[], &semantic, &AnalyzerOptionsBundle::default())
                .expect("unsupported profiles are the only hard load error");
        assert!(!context.is_complete());
        assert!(
            context
                .diagnostics()
                .iter()
                .any(|diagnostic| diagnostic.contains("--csharp-context-source"))
        );
    }

    #[test]
    fn csharp_context_union_deduplicates_exact_overlap_and_rejects_conflicts() {
        let analyzed = vec![source("src/Main.cs", "class Main {}")];
        let context = vec![
            source("./src/Main.cs", "class Main {}"),
            source("src/Contracts.cs", "class Contracts {}"),
            source("./src/Contracts.cs", "class Contracts {}"),
        ];
        let mut diagnostics = Vec::new();
        let merged = merged_csharp_snapshots(&analyzed, &context, &mut diagnostics);
        assert_eq!(merged.len(), 2);
        assert!(diagnostics.is_empty());
        assert_eq!(analyzed.len(), 1);

        let conflicting = vec![source("./src/Main.cs", "class Changed {}")];
        let mut diagnostics = Vec::new();
        let merged = merged_csharp_snapshots(&analyzed, &conflicting, &mut diagnostics);
        assert_eq!(merged.len(), 1);
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("different content"))
        );
    }

    #[test]
    fn csharp_context_source_content_changes_cache_identity() {
        let first = vec![source("Context.cs", "class Context {}")];
        let second = vec![source("Context.cs", "class Changed {}")];
        let mut first_parts = SemanticFingerprintParts::default();
        record_context_source_fingerprints(&first, &mut first_parts);
        let mut second_parts = SemanticFingerprintParts::default();
        record_context_source_fingerprints(&second, &mut second_parts);
        assert_ne!(
            semantic_cache_fingerprints(&first_parts).context,
            semantic_cache_fingerprints(&second_parts).context
        );
    }

    #[test]
    fn csharp_context_source_read_failures_are_diagnostics() {
        let invalid = std::env::temp_dir().join(format!(
            "hoonarqube-csharp-context-invalid-{}.cs",
            std::process::id()
        ));
        fs::write(&invalid, [0xff, 0xfe]).expect("write invalid UTF-8 fixture");
        let semantic = SemanticOptions {
            csharp_project: Some(PathBuf::from(".")),
            csharp_context_sources: vec![
                PathBuf::from("missing-context-source.cs"),
                invalid.clone(),
            ],
            ..SemanticOptions::default()
        };
        let loaded = load_csharp_context_sources(&semantic);
        let _ = fs::remove_file(&invalid);
        assert!(loaded.snapshots.is_empty());
        assert!(
            loaded
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("cannot read csharp context source"))
        );
        assert!(
            loaded
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("not valid UTF-8"))
        );
    }

    #[test]
    fn csharp_context_sources_are_not_analyzed_inventory() {
        let analyzed = vec![source("src/Main.cs", "class Main {}")];
        let original = analyzed.clone();
        let context = vec![source("src/Contracts.cs", "class Contracts {}")];
        let mut diagnostics = Vec::new();
        let _ = merged_csharp_snapshots(&analyzed, &context, &mut diagnostics);
        assert_eq!(analyzed, original);
        assert!(diagnostics.is_empty());
    }
    #[test]
    fn python_project_requires_an_existing_path_and_accepts_directory_or_file() {
        let root = std::env::temp_dir().join(format!(
            "hoonarqube-python-project-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let existing_dir = root.join("package");
        fs::create_dir_all(&existing_dir).unwrap();
        let existing_file = root.join("pyproject.toml");
        fs::write(&existing_file, "[project]\n").unwrap();

        for project in [&existing_dir, &existing_file] {
            let semantic = SemanticOptions {
                python_project: Some((*project).clone()),
                ..SemanticOptions::default()
            };
            let mut diagnostics = Vec::new();
            let mut fingerprints = SemanticFingerprintParts::default();
            assert!(
                load_python_context(&[], &semantic, &mut diagnostics, &mut fingerprints).is_some()
            );
            assert!(diagnostics.is_empty());
        }

        let missing = root.join("missing.py");
        let semantic = SemanticOptions {
            python_project: Some(missing.clone()),
            ..SemanticOptions::default()
        };
        let mut diagnostics = Vec::new();
        let mut fingerprints = SemanticFingerprintParts::default();
        assert!(load_python_context(&[], &semantic, &mut diagnostics, &mut fingerprints).is_none());
        assert!(
            diagnostics
                .iter()
                .any(|diagnostic| diagnostic.contains("python project path does not exist"))
        );
        fs::remove_dir_all(root).unwrap();
    }
}
