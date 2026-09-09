//! Path walking and per-file orchestration for the `analyze` subcommand.
//!
//! Walks requested paths, feeds each selected Python, JS/TS, C#, Go, Java,
//! Ruby, or Rust file to its language analyzer, and returns deterministic
//! issue reports plus project measurements. The project path keeps the
//! in-memory source snapshot shared by issue and source-facts analysis.
//! Non-fatal collection/read/parser problems are retained as warnings and
//! make the project report incomplete instead of being silently skipped.
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;

use globset::{Glob, GlobSet, GlobSetBuilder};
use hoonarqube_catalog::Catalog;
use hoonarqube_core::source_facts::{collect_source_facts, compiler_razor_facts};
use hoonarqube_core::{AnalyzerOptions as CoreOptions, Language};
use hoonarqube_ir::{FileClassification, MeasurementStatus, ProjectFileMeasurement};
use sha2::{Digest as _, Sha256};

use hoonarqube_core::duplication::DuplicationOptions;
use hoonarqube_core::project::{ProjectFile, analyze_project_file, build_project_report};

use crate::cache::{Cache, CacheFingerprints};
use crate::project_features::{AnalyzedSource, ProjectFeatureOptions};
use crate::semantic_cli::ProjectSemanticContext;
/// Per-language analyzer knobs shared by analyze and fix orchestration.
pub(crate) use hoonarqube_core::AnalyzerOptions as AnalyzerOptionsBundle;

pub(crate) const MAX_RETAINED_SOURCE_BYTES: usize = 256 * 1024 * 1024;
const PROJECT_INVENTORY_RECORD_OVERHEAD: usize =
    std::mem::size_of::<PathBuf>() * 2 + std::mem::size_of::<FileClassification>();

/// Raw glob lists supplied by the analyze command.
#[derive(Clone, Copy)]
pub(crate) struct ProjectPatternLists<'a> {
    pub(crate) exclude: &'a [String],
    pub(crate) test_include: &'a [String],
    pub(crate) generated_include: &'a [String],
    pub(crate) vendor_include: &'a [String],
    pub(crate) duplication_exclude: &'a [String],
}

#[derive(Clone)]
struct OwnedProjectPatternLists {
    exclude: Vec<String>,
    test_include: Vec<String>,
    generated_include: Vec<String>,
    vendor_include: Vec<String>,
    duplication_exclude: Vec<String>,
}

impl OwnedProjectPatternLists {
    fn from_lists(lists: ProjectPatternLists<'_>) -> Self {
        Self {
            exclude: lists.exclude.to_vec(),
            test_include: lists.test_include.to_vec(),
            generated_include: lists.generated_include.to_vec(),
            vendor_include: lists.vendor_include.to_vec(),
            duplication_exclude: lists.duplication_exclude.to_vec(),
        }
    }
}

#[derive(Clone)]
struct ScopeEncoder {
    bytes: Vec<u8>,
}

impl ScopeEncoder {
    fn new() -> Self {
        Self {
            bytes: b"hoonarqube-assessment-scope-v1".to_vec(),
        }
    }

    fn field(&mut self, tag: &[u8], value: &[u8]) {
        self.bytes
            .extend((u64::try_from(tag.len()).unwrap_or(u64::MAX)).to_le_bytes());
        self.bytes.extend_from_slice(tag);
        self.bytes
            .extend((u64::try_from(value.len()).unwrap_or(u64::MAX)).to_le_bytes());
        self.bytes.extend_from_slice(value);
    }

    fn list(&mut self, tag: &[u8], values: &[String]) {
        self.field(
            tag,
            &(u64::try_from(values.len()).unwrap_or(u64::MAX)).to_le_bytes(),
        );
        for value in values {
            self.field(b"value", value.as_bytes());
        }
    }

    fn finish(self) -> String {
        let digest = Sha256::digest(self.bytes);
        let mut output = String::with_capacity(digest.len() * 2);
        for byte in digest {
            use std::fmt::Write as _;
            write!(&mut output, "{byte:02x}").expect("writing to String cannot fail");
        }
        output
    }
}

/// Validated project classification and duplication patterns.
#[derive(Clone)]
pub(crate) struct ProjectPatterns {
    exclude: GlobSet,
    exclude_scope: GlobSet,
    test_include: GlobSet,
    test_include_scope: GlobSet,
    generated_include: GlobSet,
    generated_include_scope: GlobSet,
    vendor_include: GlobSet,
    vendor_include_scope: GlobSet,
    duplication_exclude: GlobSet,
}

/// Validated project settings shared by the CLI's project analysis path.
pub(crate) struct ProjectAnalysisOptions {
    pub(crate) patterns: ProjectPatterns,
    pub(crate) duplication: DuplicationOptions,
    pub(crate) cache_dir: Option<PathBuf>,
    pub(crate) features: ProjectFeatureOptions,
    raw_patterns: OwnedProjectPatternLists,
}

impl ProjectPatterns {
    fn compile(lists: ProjectPatternLists<'_>) -> Result<Self, String> {
        Ok(Self {
            exclude: compile_globset("exclude", lists.exclude)?,
            exclude_scope: compile_scope_globset("exclude", lists.exclude)?,
            test_include: compile_globset("test-include", lists.test_include)?,
            test_include_scope: compile_scope_globset("test-include", lists.test_include)?,
            generated_include: compile_globset("generated-include", lists.generated_include)?,
            generated_include_scope: compile_scope_globset(
                "generated-include",
                lists.generated_include,
            )?,
            vendor_include: compile_globset("vendor-include", lists.vendor_include)?,
            vendor_include_scope: compile_scope_globset("vendor-include", lists.vendor_include)?,
            duplication_exclude: compile_globset("duplication-exclude", lists.duplication_exclude)?,
        })
    }

    fn matches(set: &GlobSet, normalized: &Path) -> bool {
        set.is_match(normalized)
    }

    fn classify_normalized(&self, normalized: &Path) -> FileClassification {
        if Self::matches(&self.exclude, normalized) {
            FileClassification::Excluded
        } else if Self::matches(&self.vendor_include, normalized) {
            FileClassification::Vendor
        } else if Self::matches(&self.generated_include, normalized) {
            FileClassification::Generated
        } else if Self::matches(&self.test_include, normalized) {
            FileClassification::Test
        } else {
            FileClassification::Source
        }
    }

    pub(crate) fn classify(&self, path: &Path) -> FileClassification {
        self.classify_normalized(&normalized_match_path(path))
    }

    /// Classifies a directory scope using only explicit directory-root globs.
    /// A recursive pattern such as `vendor/**` contributes `vendor` to the
    /// scope set; arbitrary fabricated descendants are never probed.
    pub(crate) fn classify_scope(&self, path: &Path) -> FileClassification {
        let normalized = normalized_match_path(path);
        if Self::matches(&self.exclude, &normalized)
            || Self::matches(&self.exclude_scope, &normalized)
        {
            FileClassification::Excluded
        } else if Self::matches(&self.vendor_include, &normalized)
            || Self::matches(&self.vendor_include_scope, &normalized)
        {
            FileClassification::Vendor
        } else if Self::matches(&self.generated_include, &normalized)
            || Self::matches(&self.generated_include_scope, &normalized)
        {
            FileClassification::Generated
        } else if Self::matches(&self.test_include, &normalized)
            || Self::matches(&self.test_include_scope, &normalized)
        {
            FileClassification::Test
        } else {
            FileClassification::Source
        }
    }

    pub(crate) fn duplication_excluded(&self, path: &Path) -> bool {
        Self::matches(&self.duplication_exclude, &normalized_match_path(path))
    }
}

pub(crate) fn project_analysis_options(
    lists: ProjectPatternLists<'_>,
    min_tokens: usize,
    min_lines: u32,
    min_statements: usize,
) -> Result<ProjectAnalysisOptions, String> {
    let duplication = DuplicationOptions {
        min_tokens,
        min_lines,
        min_statements,
        ..DuplicationOptions::default()
    };
    duplication.validate()?;
    let patterns = ProjectPatterns::compile(lists)?;
    Ok(ProjectAnalysisOptions {
        patterns,
        duplication,
        cache_dir: None,
        features: ProjectFeatureOptions::default(),
        raw_patterns: OwnedProjectPatternLists::from_lists(lists),
    })
}

impl ProjectAnalysisOptions {
    fn append_scope_fields(&self, encoder: &mut ScopeEncoder) {
        encoder.list(b"exclude", &self.raw_patterns.exclude);
        encoder.list(b"test-include", &self.raw_patterns.test_include);
        encoder.list(b"generated-include", &self.raw_patterns.generated_include);
        encoder.list(b"vendor-include", &self.raw_patterns.vendor_include);
        encoder.list(
            b"duplication-exclude",
            &self.raw_patterns.duplication_exclude,
        );
        for (tag, value) in [
            (b"min-tokens".as_slice(), self.duplication.min_tokens),
            (b"min-lines".as_slice(), self.duplication.min_lines as usize),
            (
                b"min-statements".as_slice(),
                self.duplication.min_statements,
            ),
            (b"max-tokens".as_slice(), self.duplication.max_tokens),
            (
                b"max-candidate-pairs".as_slice(),
                self.duplication.max_candidate_pairs,
            ),
        ] {
            encoder.field(tag, &u64::try_from(value).unwrap_or(u64::MAX).to_le_bytes());
        }
    }

    /// Computes the stable assessment scope identity for one invocation.
    ///
    /// This is deliberately based on the effective raw CLI values rather than
    /// `GlobSet`'s implementation/debug representation. Length-delimited
    /// fields keep adjacent values unambiguous and a versioned domain makes
    /// future identity changes explicit.
    pub(crate) fn assessment_scope_digest(&self, roots: &[PathBuf]) -> String {
        let mut encoder = ScopeEncoder::new();
        let mut normalized_roots = roots
            .iter()
            .map(|root| normalized_match_path(root))
            .collect::<Vec<_>>();
        normalized_roots.sort();
        normalized_roots.dedup();
        encoder.field(
            b"roots-count",
            &u64::try_from(normalized_roots.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        for root in normalized_roots {
            encoder.field(b"root", root.as_os_str().as_encoded_bytes());
        }
        self.append_scope_fields(&mut encoder);
        encoder.finish()
    }
}

fn compile_globset(label: &str, patterns: &[String]) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let glob = Glob::new(pattern)
            .map_err(|error| format!("invalid --{label} glob {pattern:?}: {error}"))?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|error| format!("invalid --{label} globset: {error}"))
}

fn compile_scope_globset(label: &str, patterns: &[String]) -> Result<GlobSet, String> {
    let mut builder = GlobSetBuilder::new();
    for pattern in patterns {
        let Some(root) = pattern.strip_suffix("/**") else {
            continue;
        };
        let glob = Glob::new(root)
            .map_err(|error| format!("invalid --{label} scope glob {root:?}: {error}"))?;
        builder.add(glob);
    }
    builder
        .build()
        .map_err(|error| format!("invalid --{label} scope globset: {error}"))
}

fn normalized_match_path(path: &Path) -> PathBuf {
    let cwd = std::env::current_dir().unwrap_or_default();
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        cwd.join(path)
    };
    let absolute = lexical_normalize(&absolute);
    let cwd = lexical_normalize(&cwd);
    match absolute.strip_prefix(&cwd) {
        Ok(relative) if relative.as_os_str().is_empty() => PathBuf::from("."),
        Ok(relative) => relative.to_path_buf(),
        Err(_) => absolute,
    }
}

fn lexical_normalize(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                normalized.push(component.as_os_str());
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            std::path::Component::Normal(value) => normalized.push(value),
        }
    }
    normalized
}

/// Runs the project measurement path. Each readable source is loaded once and
/// the same in-memory snapshot is passed to the core project facade.
pub(crate) fn analyze_project_paths(
    paths: &[PathBuf],
    options: &AnalyzerOptionsBundle,
    project_options: &ProjectAnalysisOptions,
    warnings: &mut Vec<String>,
) -> Result<hoonarqube_ir::AnalysisReport, String> {
    let mut collected = collect_project_inputs(paths, project_options, warnings);
    let semantic = load_project_semantic_context(
        project_options,
        options,
        &collected.source_inventory,
        collected.semantic_input_complete,
        warnings,
    );
    let cache = project_cache(
        paths,
        options,
        project_options,
        collected.semantic_input_complete,
        semantic.as_ref(),
    );
    let worker_count = thread::available_parallelism()
        .map_or(1, std::num::NonZeroUsize::get)
        .min(collected.pending.len());
    collected.project_files.extend(
        analyze_project_files(
            &collected.pending,
            &collected.source_inventory,
            options,
            semantic.as_ref(),
            worker_count,
            cache.as_ref(),
        )
        .into_iter()
        .map(|(_, project_file)| project_file),
    );
    append_project_warnings(&collected.project_files, warnings);
    let unsupported_inventory = std::mem::take(&mut collected.unsupported_inventory);
    let mut report = build_project_report(
        collected.project_files,
        paths.to_vec(),
        warnings.clone(),
        &project_options.duplication,
    )?;
    append_unsupported_inventory(&mut report, unsupported_inventory);
    attach_project_assessment(
        &mut report,
        &collected.source_inventory,
        options,
        project_options,
    );
    Ok(report)
}

fn append_unsupported_inventory(
    report: &mut hoonarqube_ir::AnalysisReport,
    unsupported_inventory: Vec<(PathBuf, FileClassification)>,
) {
    let mut existing = std::collections::BTreeSet::new();
    for file in &report.project.files {
        existing.insert(normalized_input_path(&file.path));
    }
    let mut unique = std::collections::BTreeMap::new();
    for (path, classification) in unsupported_inventory {
        let key = normalized_input_path(&path);
        if existing.contains(&key) {
            continue;
        }
        match unique.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((path, classification));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if path.as_path() < entry.get().0.as_path() {
                    entry.insert((path, classification));
                }
            }
        }
    }
    for (path, _classification) in unique.into_values() {
        report.project.files.push(ProjectFileMeasurement {
            path,
            classification: FileClassification::Excluded,
            status: MeasurementStatus::Unsupported,
            metrics: None,
            duplication: None,
            reason: Some("language is unsupported".to_owned()),
        });
    }
    report
        .project
        .files
        .sort_by(|left, right| left.path.cmp(&right.path));
}

struct CollectedProjectInputs {
    project_files: Vec<ProjectFile>,
    source_inventory: Vec<AnalyzedSource>,
    pending: Vec<ProjectInput>,
    unsupported_inventory: Vec<(PathBuf, FileClassification)>,
    retained_bytes: usize,
    semantic_input_complete: bool,
}
pub(crate) type ProjectInputCollection = (
    Vec<PathBuf>,
    Vec<(PathBuf, String)>,
    Vec<(PathBuf, FileClassification)>,
    usize,
);

struct ProjectInputCollector<'a> {
    files: &'a mut Vec<PathBuf>,
    unsupported_inventory: &'a mut Vec<(PathBuf, FileClassification)>,
    unsupported_inventory_bytes: &'a mut usize,
    unsupported_inventory_overflowed: &'a mut bool,
    warnings: &'a mut Vec<String>,
}

fn collect_project_inputs(
    paths: &[PathBuf],
    project_options: &ProjectAnalysisOptions,
    warnings: &mut Vec<String>,
) -> CollectedProjectInputs {
    let retain_sources = project_options.features.assessment_requested()
        || project_options.features.semantics_requested();
    let (files, collection_failures, mut unsupported_inventory, unsupported_inventory_bytes) =
        collect_project_input_files(paths, &project_options.patterns, warnings);
    let explicit_paths: std::collections::BTreeSet<_> = files
        .iter()
        .map(|path| normalized_input_path(path))
        .collect();
    unsupported_inventory
        .retain(|(path, _)| !explicit_paths.contains(&normalized_input_path(path)));
    let mut collected = CollectedProjectInputs {
        project_files: Vec::with_capacity(files.len() + collection_failures.len()),
        source_inventory: Vec::new(),
        pending: Vec::new(),
        unsupported_inventory,
        retained_bytes: unsupported_inventory_bytes,
        semantic_input_complete: true,
    };
    let semantics_requested = project_options.features.semantics_requested();
    for (path, reason) in collection_failures {
        record_collection_failure(
            &mut collected,
            path,
            reason,
            &project_options.patterns,
            semantics_requested,
        );
    }
    for path in files {
        collect_project_input(
            path,
            &project_options.patterns,
            retain_sources,
            &mut collected,
        );
    }
    collected
}

fn record_collection_failure(
    collected: &mut CollectedProjectInputs,
    path: PathBuf,
    reason: String,
    patterns: &ProjectPatterns,
    semantics_requested: bool,
) {
    let classification = patterns.classify_scope(&path);
    if semantics_requested
        && !is_inventory_class(classification)
        && hoonarqube_core::language_for_path(&path).is_some()
    {
        collected.semantic_input_complete = false;
    }
    collected.project_files.push(ProjectFile {
        path,
        classification,
        report: None,
        facts: None,
        error: (!is_inventory_class(classification)).then_some(reason),
        duplication_excluded: false,
    });
}

fn collect_project_input(
    path: PathBuf,
    patterns: &ProjectPatterns,
    retain_sources: bool,
    collected: &mut CollectedProjectInputs,
) {
    let classification = classify_collected_path(patterns, &path);
    let duplication_excluded = patterns.duplication_excluded(&path);
    if is_inventory_class(classification) {
        collected.project_files.push(ProjectFile {
            path,
            classification,
            report: None,
            facts: None,
            error: None,
            duplication_excluded,
        });
        return;
    }
    if hoonarqube_core::language_for_path(&path).is_none() {
        // Explicit unsupported files are retained in the inventory. The
        // core builder distinguishes this no-error/no-measurement case
        // from a source read or parser failure.
        collected.project_files.push(ProjectFile {
            path,
            classification,
            report: None,
            facts: None,
            error: None,
            duplication_excluded,
        });
        return;
    }
    if retain_sources {
        collect_retained_project_input(path, classification, duplication_excluded, collected);
    } else {
        collected.pending.push(ProjectInput {
            path,
            classification,
            duplication_excluded,
            source_index: None,
        });
    }
}

fn collect_retained_project_input(
    path: PathBuf,
    classification: FileClassification,
    duplication_excluded: bool,
    collected: &mut CollectedProjectInputs,
) {
    match fs::read_to_string(&path) {
        Ok(source)
            if collected
                .retained_bytes
                .checked_add(source.len())
                .is_some_and(|bytes| bytes <= MAX_RETAINED_SOURCE_BYTES) =>
        {
            collected.retained_bytes += source.len();
            let source_index = collected.source_inventory.len();
            collected.source_inventory.push(AnalyzedSource {
                path: path.clone(),
                source,
                classification,
            });
            collected.pending.push(ProjectInput {
                path,
                classification,
                duplication_excluded,
                source_index: Some(source_index),
            });
        }
        Ok(source) => {
            collected.semantic_input_complete = false;
            collected.project_files.push(ProjectFile {
                path,
                classification,
                report: None,
                facts: None,
                error: Some(format!(
                    "retained source snapshots exceed the {MAX_RETAINED_SOURCE_BYTES} byte project limit"
                )),
                duplication_excluded,
            });
            drop(source);
        }
        Err(error) => {
            collected.semantic_input_complete = false;
            collected.project_files.push(read_failure(
                path,
                classification,
                duplication_excluded,
                &error,
            ));
        }
    }
}

fn load_project_semantic_context(
    project_options: &ProjectAnalysisOptions,
    options: &AnalyzerOptionsBundle,
    source_inventory: &[AnalyzedSource],
    semantic_input_complete: bool,
    warnings: &mut Vec<String>,
) -> Option<ProjectSemanticContext> {
    if !project_options.features.semantics_requested() {
        return None;
    }
    if !semantic_input_complete {
        warnings.push(
            "semantic context: analyzed source inventory is incomplete; compiler facts are unavailable"
                .to_owned(),
        );
        return None;
    }
    match ProjectSemanticContext::load(
        source_inventory,
        &project_options.features.semantics,
        options,
    ) {
        Ok(context) => {
            for diagnostic in context.diagnostics() {
                let warning = format!("semantic context: {diagnostic}");
                if !warnings.contains(&warning) {
                    warnings.push(warning);
                }
            }
            Some(context)
        }
        Err(error) => {
            warnings.push(format!("semantic context: {error}"));
            None
        }
    }
}

fn project_cache(
    paths: &[PathBuf],
    options: &AnalyzerOptionsBundle,
    project_options: &ProjectAnalysisOptions,
    semantic_input_complete: bool,
    semantic: Option<&ProjectSemanticContext>,
) -> Option<Cache> {
    let mut fingerprints = semantic.map_or_else(CacheFingerprints::default, |context| {
        context.cache_fingerprints().clone()
    });
    if project_options.features.assessment_requested()
        || project_options.features.semantics_requested()
    {
        fingerprints = augment_assessment_fingerprints(fingerprints, project_options, paths);
    }
    if semantic_input_complete
        && (!project_options.features.semantics_requested()
            || semantic.is_some_and(ProjectSemanticContext::is_complete))
    {
        Cache::new_with_fingerprints(project_options.cache_dir.as_deref(), options, &fingerprints)
    } else {
        None
    }
}

fn append_project_warnings(project_files: &[ProjectFile], warnings: &mut Vec<String>) {
    for project_file in project_files {
        if let Some(error) = project_file.error.as_deref()
            && !warnings.iter().any(|warning| warning.contains(error))
        {
            warnings.push(format!(
                "cannot analyze {}: {error}",
                project_file.path.display()
            ));
        }
        if let Some(facts) = project_file.facts.as_ref()
            && let Some(error) = facts.error.as_deref()
        {
            warnings.push(format!(
                "incomplete source facts for {}: {error}",
                project_file.path.display()
            ));
        }
    }
}

fn attach_project_assessment(
    report: &mut hoonarqube_ir::AnalysisReport,
    source_inventory: &[AnalyzedSource],
    options: &AnalyzerOptionsBundle,
    project_options: &ProjectAnalysisOptions,
) {
    if project_options.features.assessment_requested() {
        crate::assessment_cli::attach_assessment(
            report,
            source_inventory,
            options,
            project_options,
        );
    }
}

fn augment_assessment_fingerprints(
    fingerprints: CacheFingerprints,
    project_options: &ProjectAnalysisOptions,
    roots: &[PathBuf],
) -> CacheFingerprints {
    let scope = project_options.assessment_scope_digest(roots);
    let assessment = if project_options.features.assessment {
        b"1".as_slice()
    } else {
        b"0".as_slice()
    };
    let gate = artifact_fingerprint(
        "assessment-quality-gate-v1",
        project_options.features.quality_gate.as_deref(),
    );
    let write_baseline = artifact_fingerprint(
        "assessment-write-baseline-v1",
        project_options.features.write_baseline.as_deref(),
    );
    let reference = artifact_fingerprint(
        "assessment-baseline-v1",
        project_options.features.baseline.as_deref(),
    );
    let mut coverage_parts = vec![assessment];
    let mut coverage_fingerprints = Vec::with_capacity(
        project_options.features.coverage_lcov.len()
            + project_options.features.coverage_opencover.len(),
    );
    for path in project_options
        .features
        .coverage_lcov
        .iter()
        .chain(&project_options.features.coverage_opencover)
    {
        coverage_fingerprints.push(artifact_fingerprint("assessment-coverage-v1", Some(path)));
    }
    coverage_parts.extend(coverage_fingerprints.iter().map(String::as_bytes));
    let coverage_set = digest_feature_values("assessment-coverage-set-v1", &coverage_parts);
    CacheFingerprints {
        context: digest_feature_values(
            "cache-context-v2",
            &[fingerprints.context.as_bytes(), scope.as_bytes()],
        ),
        helper: fingerprints.helper,
        config: digest_feature_values(
            "cache-config-v2",
            &[
                fingerprints.config.as_bytes(),
                assessment,
                gate.as_bytes(),
                write_baseline.as_bytes(),
            ],
        ),
        reference: digest_feature_values(
            "cache-reference-v2",
            &[fingerprints.reference.as_bytes(), reference.as_bytes()],
        ),
        dependency: digest_feature_values(
            "cache-dependency-v2",
            &[fingerprints.dependency.as_bytes(), coverage_set.as_bytes()],
        ),
    }
}

fn artifact_fingerprint(domain: &str, path: Option<&Path>) -> String {
    let Some(path) = path else {
        return digest_feature_values(domain, &[]);
    };
    let (state, total, content_digest) = artifact_content_fingerprint(path);
    let total_bytes = total.to_le_bytes();
    digest_feature_values(
        domain,
        &[
            path.as_os_str().as_encoded_bytes(),
            state,
            &total_bytes,
            &content_digest,
        ],
    )
}

fn artifact_content_fingerprint(path: &Path) -> (&'static [u8], u64, [u8; 32]) {
    let status = if path.is_file() {
        b"present".as_slice()
    } else {
        b"missing".as_slice()
    };
    let (unreadable, total, content_digest) = read_artifact_content(path);
    let state = if unreadable {
        b"unreadable".as_slice()
    } else {
        status
    };
    (state, total, content_digest)
}

fn read_artifact_content(path: &Path) -> (bool, u64, [u8; 32]) {
    let mut content_hasher = Sha256::new();
    let mut total = 0_u64;
    let mut unreadable = false;
    if path.is_file() {
        match fs::File::open(path) {
            Ok(mut file) => {
                let mut buffer = [0_u8; 16 * 1024];
                loop {
                    let Ok(count) = file.read(&mut buffer) else {
                        unreadable = true;
                        break;
                    };
                    if count == 0 {
                        break;
                    }
                    content_hasher.update(&buffer[..count]);
                    total = total.saturating_add(u64::try_from(count).unwrap_or(u64::MAX));
                }
            }
            Err(_) => unreadable = true,
        }
    }
    let content_digest: [u8; 32] = content_hasher.finalize().into();
    (unreadable, total, content_digest)
}

fn digest_feature_values(domain: &str, values: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(
        u64::try_from(domain.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
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

struct ProjectInput {
    path: PathBuf,
    classification: FileClassification,
    duplication_excluded: bool,
    source_index: Option<usize>,
}

fn analyze_project_files(
    files: &[ProjectInput],
    sources: &[AnalyzedSource],
    options: &AnalyzerOptionsBundle,
    semantic: Option<&ProjectSemanticContext>,
    worker_count: usize,
    cache: Option<&Cache>,
) -> Vec<(usize, ProjectFile)> {
    if worker_count <= 1 {
        return files
            .iter()
            .enumerate()
            .map(|(index, file)| {
                (
                    index,
                    read_and_analyze_project(file, sources, options, semantic, cache),
                )
            })
            .collect();
    }

    let requires_jsts_stack = files.iter().any(|file| {
        matches!(
            hoonarqube_core::language_for_path(&file.path),
            Some(Language::JavaScript | Language::TypeScript)
        )
    });
    let next = AtomicUsize::new(0);
    let mut outcomes = thread::scope(|scope| {
        let background_worker_count = if requires_jsts_stack {
            worker_count
        } else {
            worker_count - 1
        };
        let mut workers = Vec::with_capacity(background_worker_count);
        for _ in 0..background_worker_count {
            let worker = if requires_jsts_stack {
                hoonarqube_core::spawn_analyzer_worker(
                    scope,
                    "hoonarqube-project-file-worker",
                    || analyze_project_pending(files, sources, options, semantic, &next, cache),
                )
            } else {
                thread::Builder::new().spawn_scoped(scope, || {
                    analyze_project_pending(files, sources, options, semantic, &next, cache)
                })
            };
            let Ok(worker) = worker else {
                break;
            };
            workers.push(worker);
        }
        let mut outcomes = if requires_jsts_stack && !workers.is_empty() {
            Vec::new()
        } else {
            analyze_project_pending(files, sources, options, semantic, &next, cache)
        };
        for worker in workers {
            outcomes.extend(
                worker
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic)),
            );
        }
        outcomes
    });
    outcomes.sort_unstable_by_key(|(index, _)| *index);
    outcomes
}

fn analyze_project_pending(
    files: &[ProjectInput],
    sources: &[AnalyzedSource],
    options: &AnalyzerOptionsBundle,
    semantic: Option<&ProjectSemanticContext>,
    next: &AtomicUsize,
    cache: Option<&Cache>,
) -> Vec<(usize, ProjectFile)> {
    let mut outcomes = Vec::new();
    loop {
        let index = next.fetch_add(1, Ordering::Relaxed);
        let Some(file) = files.get(index) else {
            return outcomes;
        };
        outcomes.push((
            index,
            read_and_analyze_project(file, sources, options, semantic, cache),
        ));
    }
}

fn read_and_analyze_project(
    input: &ProjectInput,
    sources: &[AnalyzedSource],
    options: &AnalyzerOptionsBundle,
    semantic: Option<&ProjectSemanticContext>,
    cache: Option<&Cache>,
) -> ProjectFile {
    if let Some(source_index) = input.source_index {
        let Some(snapshot) = sources.get(source_index) else {
            return ProjectFile {
                path: input.path.clone(),
                classification: input.classification,
                report: None,
                facts: None,
                error: Some("source snapshot inventory index is invalid".to_owned()),
                duplication_excluded: input.duplication_excluded,
            };
        };
        return analyze_project_source(input, &snapshot.source, options, semantic, cache);
    }
    match fs::read_to_string(&input.path) {
        Ok(source) => analyze_project_source(input, &source, options, semantic, cache),
        Err(error) => read_failure(
            input.path.clone(),
            input.classification,
            input.duplication_excluded,
            &error,
        ),
    }
}

fn analyze_project_source(
    input: &ProjectInput,
    source: &str,
    options: &AnalyzerOptionsBundle,
    semantic: Option<&ProjectSemanticContext>,
    cache: Option<&Cache>,
) -> ProjectFile {
    let content_digest = cache.map(|_| Cache::source_digest(source.as_bytes()));
    if let Some(entry) = cache
        .zip(content_digest)
        .and_then(|(cache, digest)| cache.load(&input.path, source.len(), digest))
    {
        return ProjectFile {
            path: input.path.clone(),
            classification: input.classification,
            report: Some(entry.report),
            facts: Some(entry.facts),
            error: None,
            duplication_excluded: input.duplication_excluded
                || hoonarqube_core::is_razor_path(&input.path),
        };
    }

    let (result, semantic_failed) = match semantic {
        Some(context) => match context.analyze(&input.path, source, options) {
            Ok(Some(report)) => (
                project_file_from_report(input, source, report, options, Some(context)),
                false,
            ),
            Ok(None) => (
                analyze_project_file(
                    &input.path,
                    source,
                    options,
                    input.classification,
                    input.duplication_excluded,
                ),
                false,
            ),
            Err(error) => {
                let mut result = analyze_project_file(
                    &input.path,
                    source,
                    options,
                    input.classification,
                    input.duplication_excluded,
                );
                result.error = Some(format!("semantic analysis unavailable: {error}"));
                (result, true)
            }
        },
        None => (
            analyze_project_file(
                &input.path,
                source,
                options,
                input.classification,
                input.duplication_excluded,
            ),
            false,
        ),
    };
    if !semantic_failed && let Some((cache, digest)) = cache.zip(content_digest) {
        cache.store(&input.path, digest, &result);
    }
    result
}

fn project_file_from_report(
    input: &ProjectInput,
    source: &str,
    mut report: hoonarqube_ir::FileReport,
    _options: &AnalyzerOptionsBundle,
    semantic: Option<&ProjectSemanticContext>,
) -> ProjectFile {
    let is_razor = hoonarqube_core::is_razor_path(&input.path);
    let (facts, mut error) = if is_razor {
        let compiler_facts = semantic
            .and_then(|context| context.razor_source_facts(&input.path, source))
            .and_then(|facts| compiler_razor_facts(&input.path, facts.metrics.clone()));
        if let Some(facts) = compiler_facts {
            (Some(facts), None)
        } else {
            let facts = collect_source_facts(&input.path, source);
            let error = facts
                .as_ref()
                .and_then(|facts| facts.error.clone())
                .or_else(|| {
                    Some("complete compiler-backed Razor source facts are unavailable".to_owned())
                });
            (facts, error)
        }
    } else {
        let facts = collect_source_facts(&input.path, source);
        let error = facts.as_ref().and_then(|facts| facts.error.clone());
        (facts, error)
    };
    if let Some(facts) = facts.as_ref() {
        report.metrics = facts.metrics.clone();
    } else if error.is_none() {
        error = Some("source facts unavailable for analyzed file".to_owned());
    }
    let report = if is_razor && error.is_some() {
        None
    } else {
        Some(report)
    };
    ProjectFile {
        path: input.path.clone(),
        classification: input.classification,
        report,
        facts,
        error,
        duplication_excluded: input.duplication_excluded || is_razor,
    }
}

fn read_failure(
    path: PathBuf,
    classification: FileClassification,
    duplication_excluded: bool,
    error: &std::io::Error,
) -> ProjectFile {
    let error = if error.kind() == ErrorKind::InvalidData {
        "source is not valid UTF-8".to_owned()
    } else {
        format!("cannot read file: {error}")
    };
    ProjectFile {
        path,
        classification,
        report: None,
        facts: None,
        error: Some(error),
        duplication_excluded,
    }
}

/// Resolves explicit file and directory arguments for `fix` without following
/// symlinked directories. Explicit ordinary files remain eligible for the
/// final-newline repair, while symlinked files are rejected before writes.
pub(crate) fn collect_input_files(paths: &[PathBuf], warnings: &mut Vec<String>) -> Vec<PathBuf> {
    let mut files = Vec::new();
    for path in paths {
        collect_input_path(path, &mut files, warnings);
    }
    deduplicate_input_files(files)
}

/// Collects project inputs with classification applied before any filesystem
/// probe. Excluded/generated/vendor scopes are inventoried without reading and
/// recursive scopes are pruned before the walker can descend into them.
pub(crate) fn collect_project_input_files(
    paths: &[PathBuf],
    patterns: &ProjectPatterns,
    warnings: &mut Vec<String>,
) -> ProjectInputCollection {
    let mut files = Vec::new();
    let mut failures = Vec::new();
    let mut unsupported_inventory = Vec::new();
    let mut unsupported_inventory_bytes = 0;
    let mut unsupported_inventory_overflowed = false;
    {
        let mut state = ProjectInputCollector {
            files: &mut files,
            unsupported_inventory: &mut unsupported_inventory,
            unsupported_inventory_bytes: &mut unsupported_inventory_bytes,
            unsupported_inventory_overflowed: &mut unsupported_inventory_overflowed,
            warnings,
        };
        for path in paths {
            collect_project_input_path(path, patterns, &mut state, &mut failures);
        }
    }
    let files = deduplicate_input_files(files);
    let mut unique_failures = std::collections::BTreeMap::new();
    for (path, reason) in failures {
        unique_failures
            .entry(normalized_input_path(&path))
            .or_insert((path, reason));
    }
    let mut unique_unsupported = std::collections::BTreeMap::new();
    for (path, classification) in unsupported_inventory {
        let key = normalized_input_path(&path);
        match unique_unsupported.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert((path, classification));
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if path.as_path() < entry.get().0.as_path() {
                    entry.insert((path, classification));
                }
            }
        }
    }
    (
        files,
        unique_failures.into_values().collect(),
        unique_unsupported.into_values().collect(),
        unsupported_inventory_bytes,
    )
}

fn collect_project_input_path(
    path: &Path,
    patterns: &ProjectPatterns,
    state: &mut ProjectInputCollector<'_>,
    failures: &mut Vec<(PathBuf, String)>,
) {
    let classification = patterns.classify_scope(path);
    if is_inventory_class(classification) {
        // The scope root is itself the complete inventory entry. Do not
        // inspect or enumerate an excluded/generated/vendor subtree.
        state.files.push(path.to_path_buf());
        return;
    }

    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            let warning = format!("path does not exist: {}", path.display());
            state.warnings.push(warning.clone());
            failures.push((path.to_path_buf(), warning));
            return;
        }
        Err(error) => {
            let warning = format!("cannot inspect path: {}: {error}", path.display());
            state.warnings.push(warning.clone());
            failures.push((path.to_path_buf(), warning));
            return;
        }
    };
    if metadata.file_type().is_symlink() {
        match fs::metadata(path) {
            Ok(target) if target.is_file() => state.files.push(path.to_path_buf()),
            Ok(target) if target.is_dir() => {
                let warning = format!("skipping symlinked directory: {}", path.display());
                state.warnings.push(warning);
            }
            Ok(_) => {
                let warning = format!("skipping unsupported path: {}", path.display());
                state.warnings.push(warning);
            }
            Err(error) => {
                let warning = format!("cannot inspect symlink target: {}: {error}", path.display());
                state.warnings.push(warning.clone());
                failures.push((path.to_path_buf(), warning));
            }
        }
    } else if metadata.is_dir() {
        collect_project_files(path, patterns, state);
    } else if metadata.is_file() {
        state.files.push(path.to_path_buf());
    } else {
        let warning = format!("skipping unsupported path: {}", path.display());
        state.warnings.push(warning);
    }
}

fn retain_unsupported_project_inventory(
    path: PathBuf,
    classification: FileClassification,
    state: &mut ProjectInputCollector<'_>,
) {
    let Some(cost) = path
        .as_os_str()
        .as_encoded_bytes()
        .len()
        .checked_add(PROJECT_INVENTORY_RECORD_OVERHEAD)
    else {
        if !*state.unsupported_inventory_overflowed {
            state.warnings.push(format!(
                "retained project input inventory exceeds the {MAX_RETAINED_SOURCE_BYTES} byte project limit"
            ));
            *state.unsupported_inventory_overflowed = true;
        }
        return;
    };
    let Some(total) = state.unsupported_inventory_bytes.checked_add(cost) else {
        if !*state.unsupported_inventory_overflowed {
            state.warnings.push(format!(
                "retained project input inventory exceeds the {MAX_RETAINED_SOURCE_BYTES} byte project limit"
            ));
            *state.unsupported_inventory_overflowed = true;
        }
        return;
    };
    if total > MAX_RETAINED_SOURCE_BYTES {
        if !*state.unsupported_inventory_overflowed {
            state.warnings.push(format!(
                "retained project input inventory exceeds the {MAX_RETAINED_SOURCE_BYTES} byte project limit"
            ));
            *state.unsupported_inventory_overflowed = true;
        }
        return;
    }
    *state.unsupported_inventory_bytes = total;
    state.unsupported_inventory.push((path, classification));
}

fn is_inventory_class(classification: FileClassification) -> bool {
    matches!(
        classification,
        FileClassification::Excluded | FileClassification::Generated | FileClassification::Vendor
    )
}

fn classify_collected_path(patterns: &ProjectPatterns, path: &Path) -> FileClassification {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_dir() => patterns.classify_scope(path),
        Ok(metadata) if metadata.file_type().is_symlink() => match fs::metadata(path) {
            Ok(target) if target.is_dir() => patterns.classify_scope(path),
            _ => patterns.classify(path),
        },
        Ok(_) => patterns.classify(path),
        Err(_) => patterns.classify_scope(path),
    }
}
fn should_visit_project_entry(
    entry: &ignore::DirEntry,
    patterns: &ProjectPatterns,
    skipped: &std::sync::Mutex<Vec<PathBuf>>,
) -> bool {
    if entry.depth() == 0 {
        return true;
    }
    let classification = match entry.file_type() {
        Some(file_type) if file_type.is_dir() => patterns.classify_scope(entry.path()),
        _ => patterns.classify(entry.path()),
    };
    if !is_inventory_class(classification) {
        return true;
    }
    if let Ok(mut paths) = skipped.lock() {
        paths.push(entry.path().to_path_buf());
    }
    false
}

fn collect_project_files(
    directory: &Path,
    patterns: &ProjectPatterns,
    state: &mut ProjectInputCollector<'_>,
) {
    let skipped = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let skipped_filter = std::sync::Arc::clone(&skipped);
    let filter_patterns = patterns.clone();
    let mut builder = ignore::WalkBuilder::new(directory);
    builder
        .follow_links(false)
        .git_global(false)
        .hidden(true)
        .require_git(false)
        .sort_by_file_name(std::cmp::Ord::cmp)
        .filter_entry(move |entry| {
            should_visit_project_entry(entry, &filter_patterns, skipped_filter.as_ref())
        });

    for result in builder.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                state.warnings.push(format!(
                    "cannot walk directory: {}: {error}",
                    directory.display()
                ));
                continue;
            }
        };
        if entry.depth() == 0 {
            continue;
        }
        let path = entry.into_path();
        let Some(file_type) = fs::symlink_metadata(&path)
            .map(|metadata| metadata.file_type())
            .map_err(|error| {
                state
                    .warnings
                    .push(format!("cannot inspect path: {}: {error}", path.display()));
            })
            .ok()
        else {
            continue;
        };
        collect_project_walk_entry(path, file_type, patterns, state);
    }

    match skipped.lock() {
        Ok(mut skipped_paths) => state.files.extend(skipped_paths.drain(..)),
        Err(_) => state.warnings.push(format!(
            "cannot retain excluded project paths under {}",
            directory.display()
        )),
    }
}

fn collect_project_walk_entry(
    path: PathBuf,
    file_type: std::fs::FileType,
    patterns: &ProjectPatterns,
    state: &mut ProjectInputCollector<'_>,
) {
    if file_type.is_symlink() {
        collect_project_symlink(path, patterns, state);
        return;
    }
    if !file_type.is_file() {
        return;
    }
    if is_analyzable_file(&path) {
        state.files.push(path);
        return;
    }
    if is_recognized_unsupported_file(&path) {
        let classification = patterns.classify(&path);
        retain_unsupported_project_inventory(path, classification, state);
    }
}

fn collect_project_symlink(
    path: PathBuf,
    patterns: &ProjectPatterns,
    state: &mut ProjectInputCollector<'_>,
) {
    match fs::metadata(&path) {
        Ok(metadata) if metadata.is_file() => {
            if is_analyzable_file(&path) {
                state.files.push(path);
            } else if is_recognized_unsupported_file(&path) {
                let classification = patterns.classify(&path);
                retain_unsupported_project_inventory(path, classification, state);
            }
        }
        Ok(metadata) if metadata.is_dir() => {}
        Ok(_) => {}
        Err(error) => state.warnings.push(format!(
            "cannot inspect symlink target: {}: {error}",
            path.display()
        )),
    }
}

fn collect_input_path(path: &Path, files: &mut Vec<PathBuf>, warnings: &mut Vec<String>) {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == ErrorKind::NotFound => {
            warnings.push(format!("path does not exist: {}", path.display()));
            return;
        }
        Err(error) => {
            warnings.push(format!("cannot inspect path: {}: {error}", path.display()));
            return;
        }
    };
    if reject_symlinked_ancestor(path, warnings) {
        return;
    }
    if metadata.file_type().is_symlink() {
        collect_explicit_symlink(path, warnings);
    } else if metadata.is_dir() {
        collect_files(path, files, warnings);
    } else if metadata.is_file() {
        collect_explicit_file(path, files);
    } else {
        warnings.push(format!("skipping unsupported path: {}", path.display()));
    }
}

fn deduplicate_input_files(files: Vec<PathBuf>) -> Vec<PathBuf> {
    // Resolve filesystem identity for deduplication while retaining the
    // lexically smallest original spelling for I/O and report paths.
    let mut unique = std::collections::BTreeMap::new();
    for file in files {
        let key = normalized_input_path(&file);
        match unique.entry(key) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(file);
            }
            std::collections::btree_map::Entry::Occupied(mut entry) => {
                if file < *entry.get() {
                    entry.insert(file);
                }
            }
        }
    }
    let mut files: Vec<_> = unique.into_values().collect();
    files.sort();
    files
}

fn normalized_input_path(path: &Path) -> PathBuf {
    if let Some((parent, name)) = path.parent().zip(path.file_name())
        && let Ok(canonical_parent) = parent.canonicalize()
    {
        return canonical_parent.join(name);
    }
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_or_else(|_| path.to_path_buf(), |directory| directory.join(path))
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            std::path::Component::Prefix(_) | std::path::Component::RootDir => {
                normalized.push(component.as_os_str());
            }
            std::path::Component::CurDir => {}
            std::path::Component::ParentDir => {
                if !normalized.pop() {
                    normalized.push(component.as_os_str());
                }
            }
            std::path::Component::Normal(value) => normalized.push(value),
        }
    }
    normalized
}

fn reject_symlinked_ancestor(path: &Path, warnings: &mut Vec<String>) -> bool {
    match crate::first_symlinked_ancestor(path) {
        Ok(Some(ancestor)) => {
            warnings.push(format!(
                "skipping path through symlinked directory {}: {}",
                ancestor.display(),
                path.display()
            ));
            true
        }
        Ok(None) => false,
        Err(error) => {
            warnings.push(format!(
                "cannot inspect path ancestors: {}: {error}",
                path.display()
            ));
            true
        }
    }
}

fn collect_explicit_symlink(path: &Path, warnings: &mut Vec<String>) {
    match fs::metadata(path) {
        Ok(metadata) if metadata.is_dir() => {
            warnings.push(format!("skipping symlinked directory: {}", path.display()));
        }
        Ok(metadata) if metadata.is_file() => {
            warnings.push(format!("skipping symlinked file: {}", path.display()));
        }
        Ok(_) => {
            warnings.push(format!("skipping unsupported path: {}", path.display()));
        }
        Err(error) => {
            warnings.push(format!(
                "cannot inspect symlink target: {}: {error}",
                path.display()
            ));
        }
    }
}

fn collect_explicit_file(path: &Path, files: &mut Vec<PathBuf>) {
    files.push(path.to_path_buf());
}

/// Builds analyzer options from the frozen catalog's per-rule parameter
/// defaults (`python:LineLength`, `javascript:S103`, `typescript:S103`, and
/// configured C# rules);
/// any miss falls back to that language's library default so catalog edits
/// flow through without code changes.
pub(crate) fn analyzer_options_bundle(catalog: &Catalog) -> AnalyzerOptionsBundle {
    let maximum_line_length = |rule_key: &str| {
        catalog
            .rule(rule_key)
            .and_then(|rule| {
                rule.parameters
                    .iter()
                    .find(|parameter| parameter.key == "maximumLineLength")
            })
            .and_then(|parameter| parameter.default_value.as_deref())
            .and_then(|value| value.parse::<u32>().ok())
    };
    let parameter = |rule_key: &str, key: &str| {
        catalog
            .rule(rule_key)
            .and_then(|rule| {
                rule.parameters
                    .iter()
                    .find(|parameter| parameter.key == key)
            })
            .and_then(|parameter| parameter.default_value.as_deref())
    };
    let python = match maximum_line_length("python:LineLength") {
        Some(maximum_line_length) => hoonarqube_core::PythonAnalyzerOptions {
            maximum_line_length,
            ..hoonarqube_core::PythonAnalyzerOptions::default()
        },
        None => hoonarqube_core::PythonAnalyzerOptions::default(),
    };
    let jsts =
        match maximum_line_length("javascript:S103").or(maximum_line_length("typescript:S103")) {
            Some(maximum_line_length) => hoonarqube_core::JstsAnalyzerOptions {
                maximum_line_length,
                ..hoonarqube_core::JstsAnalyzerOptions::default()
            },
            None => hoonarqube_core::JstsAnalyzerOptions::default(),
        };
    let csharp = hoonarqube_core::CSharpAnalyzerOptions {
        maximum_line_length: maximum_line_length("csharpsquid:S103").unwrap_or(200),
        maximum_file_loc_threshold: parameter("csharpsquid:S104", "maximumFileLocThreshold")
            .and_then(|value| value.parse().ok())
            .unwrap_or(1000),
        ..hoonarqube_core::CSharpAnalyzerOptions::default()
    };
    let go = hoonarqube_core::GoAnalyzerOptions {
        maximum_line_length: maximum_line_length("go:S103").unwrap_or(120) as usize,
        maximum_lines_of_code: parameter("go:S104", "Max")
            .and_then(|value| value.parse().ok())
            .unwrap_or(750),
        maximum_expression_complexity: parameter("go:S1067", "max")
            .and_then(|value| value.parse().ok())
            .unwrap_or(3),
        maximum_function_parameters: parameter("go:S107", "Max")
            .and_then(|value| value.parse().ok())
            .unwrap_or(7),
        maximum_case_lines: parameter("go:S1151", "max")
            .and_then(|value| value.parse().ok())
            .unwrap_or(6),
        duplicate_string_threshold: parameter("go:S1192", "threshold")
            .and_then(|value| value.parse().ok())
            .unwrap_or(3),
        maximum_nesting_depth: parameter("go:S134", "max")
            .and_then(|value| value.parse().ok())
            .unwrap_or(4),
        maximum_function_lines: parameter("go:S138", "max")
            .and_then(|value| value.parse().ok())
            .unwrap_or(120),
        maximum_switch_cases: parameter("go:S1479", "maximum")
            .and_then(|value| value.parse().ok())
            .unwrap_or(30),
        maximum_cognitive_complexity: parameter("go:S3776", "threshold")
            .and_then(|value| value.parse().ok())
            .unwrap_or(15),
        header_format: parameter("go:S1451", "headerFormat")
            .unwrap_or_default()
            .to_string(),
    };
    let rust = hoonarqube_core::RustAnalyzerOptions {
        maximum_function_parameters: 7,
        maximum_cognitive_complexity: parameter("rust:S3776", "threshold")
            .and_then(|value| value.parse().ok())
            .unwrap_or(15),
    };
    CoreOptions {
        profile: hoonarqube_core::RuleProfile::SonarParity,
        python,
        jsts,
        csharp,
        go,
        java: hoonarqube_core::JavaAnalyzerOptions::default(),
        rust,
        ruby: hoonarqube_core::RubyAnalyzerOptions::default(),
    }
}

/// Iteratively collects supported source files under `directory` for `fix`.
///
/// Repository ignore files and dot entries are honored, entries are visited
/// in deterministic name order, symlinked directories are never followed, and
/// symlinked files are rejected before any possible write.
pub(crate) fn collect_files(
    directory: &Path,
    files: &mut Vec<PathBuf>,
    warnings: &mut Vec<String>,
) {
    let mut builder = ignore::WalkBuilder::new(directory);
    builder
        .follow_links(false)
        .git_global(false)
        .hidden(true)
        .require_git(false)
        .sort_by_file_name(std::cmp::Ord::cmp);
    for result in builder.build() {
        let entry = match result {
            Ok(entry) => entry,
            Err(error) => {
                warnings.push(format!(
                    "cannot walk directory: {}: {error}",
                    directory.display()
                ));
                continue;
            }
        };
        if entry.depth() == 0 {
            continue;
        }
        let path = entry.into_path();
        let Some(file_type) = fs::symlink_metadata(&path)
            .map(|metadata| metadata.file_type())
            .map_err(|error| {
                warnings.push(format!("cannot inspect path: {}: {error}", path.display()));
            })
            .ok()
        else {
            continue;
        };
        if file_type.is_symlink() {
            match fs::metadata(&path) {
                Ok(metadata) if metadata.is_file() => {
                    warnings.push(format!("skipping symlinked file: {}", path.display()));
                }
                Ok(metadata) if metadata.is_dir() => {
                    warnings.push(format!("skipping symlinked directory: {}", path.display()));
                }
                Err(error) => warnings.push(format!(
                    "cannot inspect symlink target: {}: {error}",
                    path.display()
                )),
                Ok(_) => {}
            }
        } else if file_type.is_file() && is_analyzable_file(&path) {
            files.push(path);
        }
    }
}

/// One source of truth for extension dispatch, via the core registry:
/// [`hoonarqube_core::language_for_path`] covers all supported languages.
fn is_analyzable_file(path: &Path) -> bool {
    hoonarqube_core::language_for_path(path).is_some()
}

/// Recognizes Sonar-shaped CSS, web-template, and Docker paths that have no
/// native analyzer yet. Native dispatch wins first so a future or overlapping
/// extension can never be reclassified as unsupported.
fn is_recognized_unsupported_file(path: &Path) -> bool {
    if is_analyzable_file(path) {
        return false;
    }
    let extension = path.extension().and_then(|extension| extension.to_str());
    if extension.is_some_and(|extension| {
        [
            "css", "less", "scss", "sass", "html", "xhtml", "cshtml", "vbhtml", "aspx", "ascx",
            "rhtml", "erb", "shtm", "shtml", "cmp", "twig", "htm",
        ]
        .iter()
        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
    }) {
        return true;
    }
    path.file_name()
        .and_then(|file_name| file_name.to_str())
        .is_some_and(|file_name| {
            file_name.eq_ignore_ascii_case("dockerfile")
                || file_name.to_ascii_lowercase().ends_with(".dockerfile")
        })
}
#[cfg(test)]
mod tests {
    use super::*;

    use std::env;

    /// Unique temp directory under `std::env::temp_dir()`; removed on drop.
    struct TempDir(PathBuf);

    impl TempDir {
        fn new(label: &str) -> Self {
            const MAX_ATTEMPTS: u64 = 100;
            static NEXT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
            let pid = std::process::id();
            for _ in 0..MAX_ATTEMPTS {
                let id = NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let path = env::temp_dir().join(format!("hoonarqube-cli-{label}-{pid}-{id}"));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => (),
                    Err(error) => panic!("create temp dir {} for {label}: {error}", path.display()),
                }
            }
            panic!("create temp dir for {label} (pid {pid}): exhausted {MAX_ATTEMPTS} attempts");
        }

        fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.0.join(relative);
            fs::create_dir_all(path.parent().expect("parent")).expect("create parent");
            fs::write(&path, contents).expect("write fixture");
            path
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn project_options() -> ProjectAnalysisOptions {
        project_analysis_options(
            ProjectPatternLists {
                exclude: &[],
                test_include: &[],
                generated_include: &[],
                vendor_include: &[],
                duplication_exclude: &[],
            },
            100,
            10,
            10,
        )
        .expect("valid project options")
    }

    fn run_project(
        paths: &[PathBuf],
        options: &ProjectAnalysisOptions,
        warnings: &mut Vec<String>,
    ) -> hoonarqube_ir::AnalysisReport {
        analyze_project_paths(paths, &AnalyzerOptionsBundle::default(), options, warnings)
            .expect("project report")
    }

    #[test]
    fn project_walk_selects_only_source_files_sorted_by_path() {
        let fix = TempDir::new("select");
        fix.write("b.py", "y = 2\n");
        fix.write("a.py", "x = 1\n");
        fix.write("c.txt", "not source\n");
        fix.write("d.ts", "eval('x');\n");
        fix.write("e.js", "eval('y');\n");
        fix.write("sub/inner.py", "z = 3\n");
        fix.write(".hidden/skipme.py", "exec('z')\n");

        let mut warnings = Vec::new();
        let report = run_project(
            std::slice::from_ref(&fix.0),
            &project_options(),
            &mut warnings,
        );
        let paths: Vec<_> = report.files.iter().map(|file| file.path.clone()).collect();
        assert_eq!(
            paths,
            vec![
                fix.0.join("a.py"),
                fix.0.join("b.py"),
                fix.0.join("d.ts"),
                fix.0.join("e.js"),
                fix.0.join("sub").join("inner.py"),
            ]
        );
        assert!(warnings.is_empty());
    }

    #[test]
    fn project_walk_honors_gitignore_but_explicit_files_remain_analyzable() {
        let fix = TempDir::new("gitignore");
        fix.write(".gitignore", "target/\n");
        fix.write("src/kept.py", "value = 1\n");
        let ignored = fix.write("target/generated.py", "exec(user_input)\n");

        let mut walk_warnings = Vec::new();
        let walked = run_project(
            std::slice::from_ref(&fix.0),
            &project_options(),
            &mut walk_warnings,
        );
        assert_eq!(walked.files.len(), 1);
        assert_eq!(walked.files[0].path, fix.0.join("src/kept.py"));
        assert!(walk_warnings.is_empty());

        let mut explicit_warnings = Vec::new();
        let explicit = run_project(
            std::slice::from_ref(&ignored),
            &project_options(),
            &mut explicit_warnings,
        );
        assert_eq!(explicit.files.len(), 1);
        assert_eq!(explicit.files[0].path, ignored);
        assert!(explicit_warnings.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn project_walk_skips_symlinked_directories_but_reads_symlinked_files() {
        let fix = TempDir::new("symlink");
        let real = fix.write("real.py", "x = 1\n");
        fix.write("target/nested.py", "y = 2\n");
        std::os::unix::fs::symlink(fix.0.join("target"), fix.0.join("linked-dir"))
            .expect("symlink dir");
        std::os::unix::fs::symlink(&real, fix.0.join("alias.py")).expect("symlink file");

        let mut warnings = Vec::new();
        let report = run_project(
            std::slice::from_ref(&fix.0),
            &project_options(),
            &mut warnings,
        );
        let paths: Vec<_> = report.files.iter().map(|file| file.path.clone()).collect();
        assert_eq!(
            paths,
            vec![fix.0.join("alias.py"), real, fix.0.join("target/nested.py"),]
        );
        assert!(warnings.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn project_walk_warns_for_dangling_symlinks() {
        let fix = TempDir::new("dangling-symlink");
        let dangling = fix.0.join("dead.py");
        std::os::unix::fs::symlink(fix.0.join("missing.py"), &dangling).expect("dangling symlink");

        let mut warnings = Vec::new();
        let report = run_project(
            std::slice::from_ref(&fix.0),
            &project_options(),
            &mut warnings,
        );

        assert!(report.files.is_empty());
        assert!(
            report
                .project
                .warnings
                .iter()
                .any(|warning| warning.starts_with("cannot inspect symlink target: "))
        );
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains(&dangling.display().to_string()))
        );
    }

    #[test]
    fn project_reports_invalid_utf8_as_failed_inventory() {
        let fix = TempDir::new("invalid-utf8");
        let source = fix.0.join("invalid.py");
        fs::write(&source, [0xff, 0xfe, b'\n']).expect("write invalid source");

        let mut warnings = Vec::new();
        let report = run_project(
            std::slice::from_ref(&source),
            &project_options(),
            &mut warnings,
        );

        assert!(report.files.is_empty());
        let measurement = report
            .project
            .files
            .iter()
            .find(|file| file.path == source)
            .expect("failed source inventory");
        assert_eq!(measurement.status, hoonarqube_ir::MeasurementStatus::Failed);
        assert!(measurement.metrics.is_none());
        assert!(
            report
                .project
                .warnings
                .iter()
                .any(|warning| warning.contains("source is not valid UTF-8"))
        );
    }

    #[test]
    fn project_warnings_are_deterministic_for_multiple_read_failures() {
        let fix = TempDir::new("parallel-warning-order");
        for name in ["a.py", "b.py", "c.py", "d.py"] {
            fs::write(fix.0.join(name), [0xff, b'\n']).expect("write invalid source");
        }

        let mut warnings = Vec::new();
        let report = run_project(
            std::slice::from_ref(&fix.0),
            &project_options(),
            &mut warnings,
        );
        assert!(
            report
                .project
                .warnings
                .windows(2)
                .all(|pair| pair[0] <= pair[1])
        );
        assert_eq!(report.project.files.len(), 4);
    }

    #[test]
    fn fix_collection_keeps_explicit_ordinary_files_for_newline_repairs() {
        let fix = TempDir::new("fix-ordinary");
        let readme = fix.write("README.md", "# notes");
        let source = fix.write("source.py", "value = 1");

        let mut warnings = Vec::new();
        let files = collect_input_files(&[readme.clone(), source.clone()], &mut warnings);

        assert_eq!(files, vec![readme, source]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn lexical_normalization_falls_back_when_parent_is_missing() {
        let fix = TempDir::new("lexical-fallback");
        let path = fix.0.join("missing-parent").join("..").join("b.py");

        assert_eq!(normalized_input_path(&path), fix.0.join("b.py"));
    }

    #[test]
    fn warns_when_an_explicit_child_has_a_non_directory_parent() {
        let fix = TempDir::new("non-directory-parent");
        let parent = fix.write("file", "not a directory");
        let child = parent.join("child.py");

        let mut warnings = Vec::new();
        let files = collect_input_files(&[child], &mut warnings);

        assert!(files.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("cannot inspect path: "));
    }

    #[test]
    fn project_deduplicates_overlapping_explicit_and_walked_paths() {
        let fix = TempDir::new("overlap");
        fix.write("a.py", "x = 1\n");
        fix.write("b.py", "y = 2\n");

        let mut warnings = Vec::new();
        let report = run_project(
            &[fix.0.clone(), fix.0.join("a.py"), fix.0.join("a.py")],
            &project_options(),
            &mut warnings,
        );

        let paths: Vec<_> = report.files.iter().map(|file| file.path.clone()).collect();
        assert_eq!(paths, vec![fix.0.join("a.py"), fix.0.join("b.py")]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn project_deduplicates_lexically_equivalent_paths() {
        let fix = TempDir::new("lexical-overlap");
        let source = fix.write("a.py", "x = 1\n");
        fs::create_dir(fix.0.join("nested")).expect("create nested directory");
        let equivalent = fix.0.join("nested").join("..").join("a.py");

        let mut warnings = Vec::new();
        let report = run_project(
            &[equivalent, source.clone()],
            &project_options(),
            &mut warnings,
        );

        assert_eq!(report.files.len(), 1);
        assert_eq!(report.files[0].path, source);
        assert!(warnings.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn fix_collection_rejects_explicit_and_walked_symlinked_files() {
        let target = TempDir::new("fix-symlink-target");
        target.write("outside.py", "value = 1\n");
        let fixture = TempDir::new("fix-symlink-input");
        let explicit = fixture.0.join("explicit.py");
        let walked = fixture.0.join("nested.py");
        std::os::unix::fs::symlink(target.0.join("outside.py"), &explicit)
            .expect("explicit symlink");
        std::os::unix::fs::symlink(target.0.join("outside.py"), &walked).expect("walked symlink");

        let mut explicit_warnings = Vec::new();
        let explicit_files =
            collect_input_files(std::slice::from_ref(&explicit), &mut explicit_warnings);
        assert!(explicit_files.is_empty());
        assert_eq!(explicit_warnings.len(), 1);
        assert!(explicit_warnings[0].starts_with("skipping symlinked file: "));

        let mut walked_warnings = Vec::new();
        let walked_files =
            collect_input_files(std::slice::from_ref(&fixture.0), &mut walked_warnings);
        assert!(walked_files.is_empty());
        assert_eq!(walked_warnings.len(), 2);
        assert!(
            walked_warnings
                .iter()
                .all(|warning| warning.starts_with("skipping symlinked file: "))
        );
    }

    #[cfg(unix)]
    #[test]
    fn fix_collection_rejects_files_reached_through_a_symlinked_parent() {
        let target = TempDir::new("fix-parent-symlink-target");
        let outside = target.write("nested/outside.py", "value = 1");
        let fixture = TempDir::new("fix-parent-symlink-input");
        let linked_parent = fixture.0.join("linked");
        std::os::unix::fs::symlink(target.0.join("nested"), &linked_parent)
            .expect("parent symlink");
        let linked_file = linked_parent.join("outside.py");

        let mut warnings = Vec::new();
        let files = collect_input_files(std::slice::from_ref(&linked_file), &mut warnings);

        assert!(files.is_empty());
        assert_eq!(warnings.len(), 1);
        assert!(warnings[0].starts_with("skipping path through symlinked directory "));
        assert_eq!(fs::read_to_string(outside).expect("outside"), "value = 1");
    }

    #[test]
    fn project_warns_for_missing_paths() {
        let missing = env::temp_dir().join("hoonarqube-cli-does-not-exist");

        let mut warnings = Vec::new();
        let report = run_project(&[missing], &project_options(), &mut warnings);

        assert!(report.files.is_empty());
        assert!(
            report
                .project
                .warnings
                .iter()
                .any(|warning| { warning.starts_with("path does not exist: ") })
        );
        assert!(!report.project.complete);
    }

    #[cfg(unix)]
    #[test]
    fn project_keeps_distinct_paths_across_symlink_parent() {
        let fixture = TempDir::new("symlink-parent-dedup-input");
        let local = fixture.write("bar.py", "local = 1\n");
        let outside = TempDir::new("symlink-parent-dedup-target");
        fs::create_dir(outside.0.join("nested")).expect("create symlink target directory");
        outside.write("bar.py", "outside = 1\n");
        let linked = fixture.0.join("linked");
        std::os::unix::fs::symlink(outside.0.join("nested"), &linked)
            .expect("create directory symlink");

        let through_parent = linked.join("..").join("bar.py");
        let mut warnings = Vec::new();
        let report = run_project(
            &[through_parent.clone(), local.clone()],
            &project_options(),
            &mut warnings,
        );

        let paths: Vec<_> = report.files.iter().map(|file| file.path.clone()).collect();
        assert_eq!(paths, vec![local, through_parent]);
        assert!(warnings.is_empty());
    }

    #[test]
    fn catalog_python_line_length_threshold_changes_project_report() {
        let fix = TempDir::new("line-length-threshold");
        let exact = fix.write("exact.py", &format!("value = \"{}\"\n", "a".repeat(110)));
        let over = fix.write("over.py", &format!("value = \"{}\"\n", "a".repeat(111)));

        let mut warnings = Vec::new();
        let options = project_options();
        let report = analyze_project_paths(
            &[exact, over],
            &analyzer_options_bundle(hoonarqube_catalog::embedded()),
            &options,
            &mut warnings,
        )
        .expect("project report");

        assert!(warnings.is_empty());
        let exact_report = report
            .files
            .iter()
            .find(|file| file.path.ends_with("exact.py"))
            .expect("exact threshold report");
        let over_report = report
            .files
            .iter()
            .find(|file| file.path.ends_with("over.py"))
            .expect("over threshold report");
        assert!(
            !exact_report
                .issues
                .iter()
                .any(|issue| issue.rule_key == "python:LineLength")
        );
        assert!(
            over_report
                .issues
                .iter()
                .any(|issue| issue.rule_key == "python:LineLength")
        );
    }

    #[test]
    fn explicit_unsupported_paths_remain_inventory_entries() {
        let fix = TempDir::new("nonsource");
        let readme = fix.write("README.md", "# notes\n");

        let mut warnings = Vec::new();
        let report = run_project(
            std::slice::from_ref(&readme),
            &project_options(),
            &mut warnings,
        );

        assert!(report.files.is_empty());
        let measurement = report
            .project
            .files
            .iter()
            .find(|file| file.path == readme)
            .expect("unsupported inventory entry");
        assert_eq!(
            measurement.status,
            hoonarqube_ir::MeasurementStatus::Unsupported
        );
        assert!(measurement.metrics.is_none());
    }

    #[test]
    fn directory_scope_inventories_recognized_unsupported_without_affecting_metrics() {
        let fix = TempDir::new("unsupported-scope");
        let main = fix.write("main.py", "value = 1\n");
        let style_upper = fix.write("style.CSS", "body { color: red; }\n");
        fix.write("style.css", "body { color: blue; }\n");
        fix.write("index.HTML", "<p>unsupported</p>\n");
        fix.write("index.html", "<p>unsupported</p>\n");
        fix.write("Dockerfile", "FROM scratch\n");
        fix.write("dockerfile", "FROM scratch\n");
        fix.write("notes.txt", "ordinary notes\n");

        let mut baseline_warnings = Vec::new();
        let baseline = run_project(
            std::slice::from_ref(&main),
            &project_options(),
            &mut baseline_warnings,
        );
        assert!(baseline_warnings.is_empty());

        let mut mixed_warnings = Vec::new();
        let mixed = run_project(
            std::slice::from_ref(&fix.0),
            &project_options(),
            &mut mixed_warnings,
        );
        assert!(mixed_warnings.is_empty());
        assert!(mixed.project.complete);
        assert_eq!(mixed.project.metrics, baseline.project.metrics);
        assert_eq!(mixed.project.duplication, baseline.project.duplication);
        assert!(mixed.files.iter().any(|file| file.path == main));
        assert!(
            !mixed
                .project
                .files
                .iter()
                .any(|file| file.path.ends_with("notes.txt"))
        );

        for name in [
            "style.CSS",
            "style.css",
            "index.HTML",
            "index.html",
            "Dockerfile",
            "dockerfile",
        ] {
            let path = fix.0.join(name);
            let measurement = mixed
                .project
                .files
                .iter()
                .find(|file| file.path == path)
                .expect("recognized unsupported inventory entry");
            assert_eq!(measurement.status, MeasurementStatus::Unsupported);
            assert_eq!(measurement.classification, FileClassification::Excluded);
            assert_eq!(
                measurement.reason.as_deref(),
                Some("language is unsupported")
            );
            assert!(measurement.metrics.is_none());
        }

        let mut explicit_warnings = Vec::new();
        let explicit = run_project(
            std::slice::from_ref(&style_upper),
            &project_options(),
            &mut explicit_warnings,
        );
        assert!(!explicit.project.complete);
        assert_eq!(
            explicit
                .project
                .files
                .iter()
                .find(|file| file.path == style_upper)
                .map(|file| file.status),
            Some(MeasurementStatus::Unsupported)
        );
    }
    #[test]
    fn scope_globs_only_prune_explicit_recursive_roots() {
        let named = project_analysis_options(
            ProjectPatternLists {
                exclude: &["**/__hoonarqube_scope__".to_string()],
                test_include: &[],
                generated_include: &[],
                vendor_include: &[],
                duplication_exclude: &[],
            },
            100,
            10,
            10,
        )
        .expect("valid named-file glob");

        assert_eq!(
            named.patterns.classify_scope(Path::new("src")),
            FileClassification::Source
        );
        assert_eq!(
            named
                .patterns
                .classify(Path::new("src/__hoonarqube_scope__")),
            FileClassification::Excluded
        );
        assert_eq!(
            normalized_match_path(&env::current_dir().expect("current directory")),
            PathBuf::from(".")
        );
    }

    #[test]
    fn project_inventory_retains_pruned_directory_roots_without_descendants() {
        let fix = TempDir::new("inventory-roots");
        let source = fix.write("src/main.py", "value = 1\n");
        let excluded_file = fix.write("ignored/secret.py", "value = 2\n");
        let generated_file = fix.write("generated/build.py", "value = 3\n");
        let vendor_file = fix.write("vendor/library.py", "value = 4\n");
        let root_glob = |name: &str| format!("{}/{}", fix.0.display(), name);
        let exclude = vec![format!("{}/**", root_glob("ignored"))];
        let generated = vec![format!("{}/**", root_glob("generated"))];
        let vendor = vec![format!("{}/**", root_glob("vendor"))];
        let options = project_analysis_options(
            ProjectPatternLists {
                exclude: &exclude,
                test_include: &[],
                generated_include: &generated,
                vendor_include: &vendor,
                duplication_exclude: &[],
            },
            100,
            10,
            10,
        )
        .expect("valid inventory options");

        let mut warnings = Vec::new();
        let report = run_project(std::slice::from_ref(&fix.0), &options, &mut warnings);

        assert!(warnings.is_empty());
        assert!(report.files.iter().any(|file| file.path == source));
        assert!(!report.files.iter().any(|file| file.path == excluded_file));
        assert!(!report.files.iter().any(|file| file.path == generated_file));
        assert!(!report.files.iter().any(|file| file.path == vendor_file));
        for (path, classification) in [
            (fix.0.join("ignored"), FileClassification::Excluded),
            (fix.0.join("generated"), FileClassification::Generated),
            (fix.0.join("vendor"), FileClassification::Vendor),
        ] {
            let measurement = report
                .project
                .files
                .iter()
                .find(|file| file.path == path)
                .expect("pruned scope root");
            assert_eq!(measurement.classification, classification);
            assert_eq!(
                measurement.status,
                hoonarqube_ir::MeasurementStatus::Excluded
            );
            assert!(measurement.metrics.is_none());
        }
    }

    #[test]
    fn inaccessible_excluded_scope_remains_an_inventory_entry() {
        let fix = TempDir::new("inaccessible-inventory-root");
        let root = fix.0.join("missing");
        let exclude = vec![format!("{}/**", root.display())];
        let options = project_analysis_options(
            ProjectPatternLists {
                exclude: &exclude,
                test_include: &[],
                generated_include: &[],
                vendor_include: &[],
                duplication_exclude: &[],
            },
            100,
            10,
            10,
        )
        .expect("valid inaccessible scope options");

        let mut warnings = Vec::new();
        let report = run_project(std::slice::from_ref(&root), &options, &mut warnings);

        assert!(warnings.is_empty());
        let measurement = report
            .project
            .files
            .iter()
            .find(|file| file.path == root)
            .expect("inaccessible excluded root");
        assert_eq!(measurement.classification, FileClassification::Excluded);
        assert_eq!(
            measurement.status,
            hoonarqube_ir::MeasurementStatus::Excluded
        );
        assert!(measurement.metrics.is_none());
    }

    #[test]
    fn parses_catalog_line_length_defaults_per_language() {
        let catalog = hoonarqube_catalog::embedded();
        let options = analyzer_options_bundle(catalog);
        assert_eq!(options.python.maximum_line_length, 120);
        assert_eq!(options.jsts.maximum_line_length, 180);
    }

    #[test]
    fn csharp_header_defaults_remain_disabled() {
        let options = analyzer_options_bundle(hoonarqube_catalog::embedded());

        assert!(options.csharp.header_format.is_empty());
        assert!(!options.csharp.header_is_regular_expression);
    }

    #[test]
    fn project_patterns_use_explicit_precedence_and_validation() {
        let exclude = vec!["src/**".to_string()];
        let test_include = vec!["**/*_test.py".to_string()];
        let generated_include = vec!["**/generated/**".to_string()];
        let vendor_include = vec!["**/vendor/**".to_string()];
        let duplication_exclude = vec!["src/large.py".to_string()];
        let options = project_analysis_options(
            ProjectPatternLists {
                exclude: &exclude,
                test_include: &test_include,
                generated_include: &generated_include,
                vendor_include: &vendor_include,
                duplication_exclude: &duplication_exclude,
            },
            100,
            10,
            10,
        )
        .expect("valid project options");

        assert_eq!(
            options
                .patterns
                .classify(Path::new("src/vendor/generated/foo_test.py")),
            FileClassification::Excluded
        );
        assert_eq!(
            options
                .patterns
                .classify(Path::new("vendor/generated/foo_test.py")),
            FileClassification::Vendor
        );
        assert_eq!(
            options
                .patterns
                .classify(Path::new("generated/foo_test.py")),
            FileClassification::Generated
        );
        assert_eq!(
            options.patterns.classify(Path::new("unit/foo_test.py")),
            FileClassification::Test
        );
        assert_eq!(
            options.patterns.classify(Path::new("src/large.py")),
            FileClassification::Excluded
        );
        assert_eq!(
            options.patterns.classify_scope(Path::new("src")),
            FileClassification::Excluded
        );
        assert_eq!(
            options.patterns.classify_scope(Path::new("vendor")),
            FileClassification::Vendor
        );
        assert_eq!(
            options.patterns.classify_scope(Path::new("generated")),
            FileClassification::Generated
        );
        assert!(
            options
                .patterns
                .duplication_excluded(Path::new("src/large.py"))
        );
        assert!(
            project_analysis_options(
                ProjectPatternLists {
                    exclude: &[],
                    test_include: &[],
                    generated_include: &[],
                    vendor_include: &[],
                    duplication_exclude: &["[".to_string()],
                },
                100,
                10,
                10,
            )
            .is_err()
        );
        assert!(
            project_analysis_options(
                ProjectPatternLists {
                    exclude: &[],
                    test_include: &[],
                    generated_include: &[],
                    vendor_include: &[],
                    duplication_exclude: &[],
                },
                0,
                10,
                10,
            )
            .is_err()
        );
    }
}
