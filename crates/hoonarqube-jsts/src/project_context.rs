//! Opt-in TypeScript compiler-backed project context.
//!
//! The ordinary [`crate::analyze`] API deliberately remains a standalone Oxc
//! analysis.  This module is the additive project API: the caller supplies the
//! exact source snapshots that the CLI is analysing, and one bounded helper
//! process creates typed/module facts for the whole project.  Semantic rules
//! consume only those facts.  Missing compiler/configuration/reference input is
//! represented as an explicit incomplete context and never as a zero-finding
//! successful analysis.

use crate::rules::semantic_context;
use crate::support::sort_issues;
use crate::{AnalyzerOptions, JstsLanguage};
use hoonarqube_ir::FileReport;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const HELPER_PROTOCOL_VERSION: u32 = 1;
const DEFAULT_COMPILER_VERSION: &str = "6.0.3";
const DEFAULT_MAX_OUTPUT_BYTES: usize = 8 * 1024 * 1024;
const EMBEDDED_HELPER: &str =
    include_str!("../../../tools/semantic/typescript/semantic-helper.cjs");

/// Configuration for one compiler-backed JS/TS project analysis.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeScriptProjectConfig {
    /// Project root used for tsconfig, package, and module-resolution scope.
    pub root: PathBuf,
    /// The root tsconfig. `None` requests compiler defaults with the supplied
    /// snapshots as roots; a missing configured file is incomplete.
    pub tsconfig: Option<PathBuf>,
    /// Directory containing the project-local `typescript` package.  The
    /// helper never searches globally and never downloads a compiler.
    pub typescript_package: Option<PathBuf>,
    /// Executable used to run the helper, normally `node`.
    pub helper_program: PathBuf,
    /// Optional explicit helper script.  If absent, the pinned source is
    /// materialised under `helper_cache_dir` before invocation.
    pub helper_script: Option<PathBuf>,
    /// Arguments inserted between `helper_program` and the helper script.
    pub helper_args: Vec<OsString>,
    /// Owned deterministic location for the embedded helper source.
    pub helper_cache_dir: PathBuf,
    /// Exact compiler version accepted by this context.
    pub expected_compiler_version: String,
    /// Maximum helper stdout accepted by the loader.
    pub max_output_bytes: usize,
    /// S4328 package names that are explicitly allowed by project policy.
    pub dependency_whitelist: Vec<String>,
}

impl TypeScriptProjectConfig {
    /// Creates a strict project config using the pinned TypeScript 6.0.3
    /// helper contract.  Call [`Self::without_tsconfig`] for a config-less
    /// project whose source roots are supplied directly.
    #[must_use]
    pub fn new(root: impl AsRef<Path>) -> Self {
        let root = canonical_path(root.as_ref());
        Self {
            tsconfig: Some(root.join("tsconfig.json")),
            helper_cache_dir: root.join(".hoonarqube/semantic/typescript"),
            root,
            typescript_package: None,
            helper_program: PathBuf::from("node"),
            helper_script: None,
            helper_args: Vec::new(),
            expected_compiler_version: DEFAULT_COMPILER_VERSION.to_owned(),
            max_output_bytes: DEFAULT_MAX_OUTPUT_BYTES,
            dependency_whitelist: Vec::new(),
        }
    }

    /// Creates a project config without requiring a tsconfig file.
    #[must_use]
    pub fn without_tsconfig(root: PathBuf) -> Self {
        let mut config = Self::new(root);
        config.tsconfig = None;
        config
    }

    /// Uses an explicit helper executable/script, useful for a packaged CLI.
    #[must_use]
    pub fn with_helper(mut self, program: PathBuf, script: PathBuf) -> Self {
        self.helper_program = program;
        self.helper_script = Some(script);
        self
    }

    /// Uses the project-local TypeScript package directory.
    #[must_use]
    pub fn with_typescript_package(mut self, package_root: impl AsRef<Path>) -> Self {
        self.typescript_package = Some(canonical_path(package_root.as_ref()));
        self
    }

    /// Replaces the S4328 whitelist with package names or scopes.
    #[must_use]
    pub fn with_dependency_whitelist(mut self, whitelist: Vec<String>) -> Self {
        self.dependency_whitelist = whitelist;
        self
    }
}

/// One exact source snapshot.  The digest is computed at construction and is
/// checked both before invocation and against helper output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticSourceSnapshot {
    pub path: PathBuf,
    pub source: String,
    pub digest: String,
}

impl SemanticSourceSnapshot {
    #[must_use]
    pub fn new(path: impl AsRef<Path>, source: String) -> Self {
        let path = canonical_path(path.as_ref());
        let digest = digest_bytes(source.as_bytes());
        Self {
            path,
            source,
            digest,
        }
    }
}

/// Exact source set sent to one helper invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ProjectSemanticSources {
    pub files: Vec<SemanticSourceSnapshot>,
}

impl ProjectSemanticSources {
    #[must_use]
    pub fn new(files: Vec<SemanticSourceSnapshot>) -> Self {
        Self { files }
    }

    #[must_use]
    pub fn from_pairs(files: impl IntoIterator<Item = (PathBuf, String)>) -> Self {
        Self {
            files: files
                .into_iter()
                .map(|(path, source)| SemanticSourceSnapshot::new(path, source))
                .collect(),
        }
    }

    pub fn push(&mut self, path: PathBuf, source: String) {
        self.files.push(SemanticSourceSnapshot::new(path, source));
    }
}

/// Context completeness is intentionally explicit.  `Incomplete` contexts
/// retain diagnostics/fingerprint for reporting and cache invalidation but do
/// not produce semantic rule findings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectSemanticStatus {
    Complete,
    Incomplete,
}

/// Structured compiler/helper diagnostic.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticDiagnostic {
    pub code: String,
    pub message: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub start: Option<u32>,
    #[serde(default)]
    pub end: Option<u32>,
}

/// Process or protocol failure while loading the context.  A valid helper
/// response containing compiler diagnostics returns an incomplete context
/// instead of this error so callers can preserve all structured diagnostics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectContextError {
    pub code: String,
    pub message: String,
    pub diagnostics: Vec<SemanticDiagnostic>,
}

impl std::fmt::Display for ProjectContextError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for ProjectContextError {}

/// One compiler-produced file fact set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SemanticFileFacts {
    pub path: PathBuf,
    pub source_digest: String,
    #[serde(default)]
    pub language: String,
    #[serde(default)]
    pub module_kind: String,
    #[serde(default)]
    pub facts: SemanticFacts,
    #[serde(default)]
    pub imports: Vec<SemanticImportFact>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SemanticFacts {
    #[serde(default)]
    pub deprecated: Vec<DeprecatedFact>,
    #[serde(default)]
    pub assertions: Vec<AssertionFact>,
    #[serde(default)]
    pub nullish: Vec<NullishFact>,
    #[serde(default)]
    pub usages: Vec<SymbolUsageFact>,
    #[serde(default)]
    pub quickfixes: Vec<SemanticQuickfixFact>,
}

impl SemanticFacts {
    #[must_use = "use the iterator to inspect matching compiler quick-fix facts"]
    pub fn quickfixes_for(
        &self,
        rule_key: &str,
        subject_span: SemanticSpan,
    ) -> impl Iterator<Item = &SemanticQuickfixFact> {
        let requested = rule_key.rsplit(':').next().unwrap_or(rule_key);
        self.quickfixes.iter().filter(move |fact| {
            fact.rule_key.rsplit(':').next().unwrap_or(&fact.rule_key) == requested
                && fact.subject_span == subject_span
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticSpan {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeprecatedFact {
    pub span: SemanticSpan,
    pub message: String,
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(default)]
    pub declaration_path: Option<PathBuf>,
    #[serde(default)]
    pub diagnostic: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SymbolUsageFact {
    pub span: SemanticSpan,
    pub name: String,
    #[serde(default)]
    pub symbol: Option<String>,
    #[serde(default)]
    pub declaration_path: Option<PathBuf>,
}

/// A compiler-proven IDE quick-fix plan attached to one stable AST subject.
///
/// Facts are advisory only: native findings still decide whether an action is
/// surfaced.  Empty `actions` is an explicit checker-known no-action result.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticQuickfixFact {
    pub rule_key: String,
    pub subject_span: SemanticSpan,
    #[serde(default)]
    pub actions: Vec<SemanticQuickfixAction>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticQuickfixAction {
    pub id: String,
    pub message: String,
    #[serde(default)]
    pub edits: Vec<SemanticQuickfixEdit>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticQuickfixEdit {
    pub span: SemanticSpan,
    pub replacement: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
// Compiler type flags are orthogonal evidence and intentionally preserve the wire schema.
#[allow(clippy::struct_excessive_bools)]
pub struct TypeInfo {
    #[serde(default)]
    pub text: String,
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub constituents: Vec<TypeConstituent>,
    #[serde(default)]
    pub has_null: bool,
    #[serde(default)]
    pub has_undefined: bool,
    #[serde(default)]
    pub has_object: bool,
    #[serde(default)]
    pub has_primitive: bool,
    #[serde(default)]
    pub has_falsy_primitive: bool,
    #[serde(default)]
    pub has_any: bool,
    #[serde(default)]
    pub has_unknown: bool,
    #[serde(default)]
    pub has_never: bool,
    #[serde(default)]
    pub has_type_parameter: bool,
    #[serde(default)]
    pub is_union: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeConstituent {
    #[serde(default)]
    pub flags: Vec<String>,
    #[serde(default)]
    pub text: String,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
// Compiler assertion flags are independent evidence and intentionally preserve the wire schema.
#[allow(clippy::struct_excessive_bools)]
pub struct AssertionFact {
    pub kind: String,
    pub span: SemanticSpan,
    pub source: TypeInfo,
    pub target: TypeInfo,
    #[serde(default)]
    pub equivalent: bool,
    #[serde(default)]
    pub generic_call: bool,
    #[serde(default)]
    pub unnecessary: bool,
    #[serde(default)]
    pub strict_null_checks: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NullishFact {
    pub kind: String,
    pub span: SemanticSpan,
    pub left_span: SemanticSpan,
    #[serde(default)]
    pub right_span: Option<SemanticSpan>,
    pub left: TypeInfo,
    #[serde(default)]
    pub report: bool,
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
// Compiler import flags are independent evidence and intentionally preserve the wire schema.
#[allow(clippy::struct_excessive_bools)]
pub struct SemanticImportFact {
    pub kind: String,
    pub module: String,
    pub span: SemanticSpan,
    /// Exact S4328 location: the `import` keyword or `require` callee.
    /// Ineligible import forms intentionally omit this proof.
    #[serde(default)]
    pub diagnostic_span: Option<SemanticSpan>,
    pub module_span: SemanticSpan,
    #[serde(default)]
    pub local_span: Option<SemanticSpan>,
    pub package: String,
    #[serde(default)]
    pub external: bool,
    #[serde(default)]
    pub declared_dependency: bool,
    #[serde(default)]
    pub dependency_exempt: bool,
    #[serde(default)]
    pub resolved: bool,
    #[serde(default)]
    pub resolved_path: Option<PathBuf>,
    /// Compiler proof that evaluating the resolved module has no observable
    /// top-level effects. `None` means the helper could not prove safety.
    #[serde(default)]
    pub side_effect_free: Option<bool>,
    #[serde(default)]
    pub external_library: bool,
    #[serde(default)]
    pub internal: bool,
    #[serde(default)]
    pub internal_reason: Option<String>,
    #[serde(default)]
    pub unresolved_reason: Option<String>,
    #[serde(default)]
    pub manifests: Vec<ManifestDigest>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManifestDigest {
    pub path: PathBuf,
    pub digest: String,
}

/// Helper/compiler dependency used in the context fingerprint.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticDependency {
    pub path: PathBuf,
    pub digest: String,
    #[serde(default)]
    pub kind: Option<String>,
}

/// Result of one file analysis through an already loaded project context.
#[derive(Debug, Clone)]
pub struct SemanticAnalysis {
    pub report: FileReport,
    pub diagnostics: Vec<SemanticDiagnostic>,
}

/// Loaded, fingerprinted TypeScript program facts.
#[derive(Debug, Clone)]
pub struct ProjectSemanticContext {
    config: TypeScriptProjectConfig,
    status: ProjectSemanticStatus,
    fingerprint: String,
    compiler_version: Option<String>,
    compiler_path: Option<PathBuf>,
    files: BTreeMap<PathBuf, SemanticFileFacts>,
    dependencies: Vec<SemanticDependency>,
    diagnostics: Vec<SemanticDiagnostic>,
}

fn validate_quickfix_facts(
    facts: &SemanticFacts,
    source: &str,
    path: &Path,
    diagnostics: &mut Vec<SemanticDiagnostic>,
) {
    let mut fact_keys = BTreeSet::new();
    for fact in &facts.quickfixes {
        if !valid_quickfix_fact(fact, source, &mut fact_keys) {
            diagnostics.push(SemanticDiagnostic {
                code: "JS_CONTEXT_INVALID_QUICKFIX".to_owned(),
                message: format!(
                    "Helper returned malformed compiler quick-fix facts for {}.",
                    path.display()
                ),
                category: "error".to_owned(),
                path: Some(path.to_owned()),
                start: Some(fact.subject_span.start),
                end: Some(fact.subject_span.end),
            });
        }
    }
}

fn valid_semantic_span(source: &str, span: &SemanticSpan) -> bool {
    span.start <= span.end
        && usize::try_from(span.end)
            .ok()
            .is_some_and(|end| end <= source.len())
        && usize::try_from(span.start)
            .ok()
            .is_some_and(|start| source.is_char_boundary(start))
        && usize::try_from(span.end)
            .ok()
            .is_some_and(|end| source.is_char_boundary(end))
}

fn valid_quickfix_fact(
    fact: &SemanticQuickfixFact,
    source: &str,
    fact_keys: &mut BTreeSet<(String, u32, u32)>,
) -> bool {
    let fact_rule = fact
        .rule_key
        .rsplit(':')
        .next()
        .unwrap_or(&fact.rule_key)
        .to_owned();
    let known_rule = matches!(
        fact_rule.as_str(),
        "S1125" | "S2871" | "S4043" | "S4322" | "S4623" | "S4782" | "S6439" | "S6594" | "S6759"
    );
    let mut valid = !fact.rule_key.trim().is_empty()
        && known_rule
        && valid_semantic_span(source, &fact.subject_span);
    if !fact_keys.insert((fact_rule, fact.subject_span.start, fact.subject_span.end)) {
        valid = false;
    }
    let mut action_ids = BTreeSet::new();
    for action in &fact.actions {
        if !valid_quickfix_action(action, source, &mut action_ids) {
            valid = false;
        }
    }
    valid
}

fn valid_quickfix_action(
    action: &SemanticQuickfixAction,
    source: &str,
    action_ids: &mut BTreeSet<String>,
) -> bool {
    if action.id.trim().is_empty()
        || action.message.trim().is_empty()
        || action.edits.is_empty()
        || !action_ids.insert(action.id.clone())
    {
        return false;
    }
    let mut ranges = Vec::with_capacity(action.edits.len());
    let mut valid = true;
    for edit in &action.edits {
        if !valid_semantic_span(source, &edit.span) {
            valid = false;
        }
        ranges.push((edit.span.start, edit.span.end));
    }
    ranges.sort_unstable();
    valid
        && !ranges
            .windows(2)
            .any(|pair| ranges_overlap(pair[0], pair[1]))
}

fn ranges_overlap(left: (u32, u32), right: (u32, u32)) -> bool {
    let (left_start, left_end) = left;
    let (right_start, right_end) = right;
    if left_start == left_end && right_start == right_end {
        left_start == right_start
    } else if left_start == left_end {
        left_start >= right_start && left_start < right_end
    } else if right_start == right_end {
        right_start >= left_start && right_start < left_end
    } else {
        left_start.max(right_start) < left_end.min(right_end)
    }
}

fn collect_source_snapshots(
    sources: &ProjectSemanticSources,
) -> (
    BTreeMap<PathBuf, SemanticSourceSnapshot>,
    Vec<SemanticDiagnostic>,
) {
    let mut diagnostics = Vec::new();
    let mut snapshots = BTreeMap::new();
    for item in &sources.files {
        let path = canonical_path(&item.path);
        let digest = digest_bytes(item.source.as_bytes());
        if digest != item.digest {
            diagnostics.push(SemanticDiagnostic {
                code: "JS_CONTEXT_SOURCE_DIGEST".to_owned(),
                message: format!("Source snapshot digest mismatch: {}", path.display()),
                category: "error".to_owned(),
                path: Some(path.clone()),
                start: None,
                end: None,
            });
            continue;
        }
        if snapshots.insert(path.clone(), item.clone()).is_some() {
            diagnostics.push(SemanticDiagnostic {
                code: "JS_CONTEXT_DUPLICATE_SOURCE".to_owned(),
                message: format!("Duplicate source snapshot: {}", path.display()),
                category: "error".to_owned(),
                path: Some(path),
                start: None,
                end: None,
            });
        }
    }
    (snapshots, diagnostics)
}

fn validate_response_metadata(
    response: &HelperResponse,
    expected_compiler_version: &str,
    diagnostics: &mut Vec<SemanticDiagnostic>,
) {
    match response.compiler_version.as_deref() {
        Some(version) if version == expected_compiler_version => {}
        Some(version) => diagnostics.push(SemanticDiagnostic {
            code: "JS_CONTEXT_COMPILER_VERSION".to_owned(),
            message: format!(
                "Helper reported TypeScript {version}, expected {expected_compiler_version}."
            ),
            category: "error".to_owned(),
            path: None,
            start: None,
            end: None,
        }),
        None => diagnostics.push(SemanticDiagnostic {
            code: "JS_CONTEXT_MISSING_COMPILER_VERSION".to_owned(),
            message: "Helper omitted the TypeScript compiler version.".to_owned(),
            category: "error".to_owned(),
            path: None,
            start: None,
            end: None,
        }),
    }
    for dependency in &response.dependencies {
        if !dependency.path.is_absolute()
            || dependency.path.as_os_str().is_empty()
            || !is_sha256(&dependency.digest)
        {
            diagnostics.push(SemanticDiagnostic {
                code: "JS_CONTEXT_INVALID_DEPENDENCY".to_owned(),
                message: "Helper returned a dependency without a canonical path or SHA-256 digest."
                    .to_owned(),
                category: "error".to_owned(),
                path: Some(dependency.path.clone()),
                start: None,
                end: None,
            });
        }
    }
}

fn collect_helper_facts(
    files: Vec<SemanticFileFacts>,
    snapshots: &BTreeMap<PathBuf, SemanticSourceSnapshot>,
    diagnostics: &mut Vec<SemanticDiagnostic>,
) -> BTreeMap<PathBuf, SemanticFileFacts> {
    let expected_paths: BTreeSet<_> = snapshots.keys().cloned().collect();
    let mut facts = BTreeMap::new();
    for item in files {
        let path = canonical_path(&item.path);
        let Some(snapshot) = snapshots.get(&path) else {
            diagnostics.push(SemanticDiagnostic {
                code: "JS_CONTEXT_UNEXPECTED_SOURCE".to_owned(),
                message: format!("Helper returned an unexpected source: {}", path.display()),
                category: "error".to_owned(),
                path: Some(path),
                start: None,
                end: None,
            });
            continue;
        };
        if item.source_digest != snapshot.digest {
            diagnostics.push(SemanticDiagnostic {
                code: "JS_CONTEXT_HELPER_SOURCE_DIGEST".to_owned(),
                message: format!("Helper source digest mismatch: {}", path.display()),
                category: "error".to_owned(),
                path: Some(path.clone()),
                start: None,
                end: None,
            });
            continue;
        }
        validate_quickfix_facts(&item.facts, &snapshot.source, &path, diagnostics);
        if facts.insert(path.clone(), item).is_some() {
            diagnostics.push(SemanticDiagnostic {
                code: "JS_CONTEXT_DUPLICATE_RESULT".to_owned(),
                message: format!("Helper returned duplicate source facts: {}", path.display()),
                category: "error".to_owned(),
                path: Some(path),
                start: None,
                end: None,
            });
        }
    }
    if facts.keys().cloned().collect::<BTreeSet<_>>() != expected_paths {
        diagnostics.push(SemanticDiagnostic {
            code: "JS_CONTEXT_INCOMPLETE_SOURCES".to_owned(),
            message: "TypeScript helper did not return exactly one fact set per source snapshot."
                .to_owned(),
            category: "error".to_owned(),
            path: None,
            start: None,
            end: None,
        });
    }
    facts
}

fn helper_fingerprint(
    response: &mut HelperResponse,
    input: &[u8],
    diagnostics: &mut Vec<SemanticDiagnostic>,
) -> String {
    if response.fingerprint.is_empty() {
        diagnostics.push(SemanticDiagnostic {
            code: "JS_CONTEXT_MISSING_FINGERPRINT".to_owned(),
            message: "TypeScript helper omitted the context fingerprint.".to_owned(),
            category: "error".to_owned(),
            path: None,
            start: None,
            end: None,
        });
        digest_bytes(input)
    } else {
        std::mem::take(&mut response.fingerprint)
    }
}

impl ProjectSemanticContext {
    /// Runs exactly one bounded compiler helper invocation for `sources`.
    ///
    /// # Errors
    ///
    /// Returns [`ProjectContextError`] when the helper cannot be prepared or
    /// invoked, or when its request or response cannot be encoded or decoded.
    pub fn load(
        config: &TypeScriptProjectConfig,
        sources: &ProjectSemanticSources,
    ) -> Result<Self, ProjectContextError> {
        let (snapshots, mut diagnostics) = collect_source_snapshots(sources);
        if diagnostics.iter().any(|item| item.category == "error") {
            return Ok(Self::incomplete(
                config.clone(),
                diagnostics,
                "source validation failed",
            ));
        }

        let materialized = materialize_helper(config).map_err(|error| ProjectContextError {
            code: "JS_CONTEXT_HELPER_PREPARE".to_owned(),
            message: error.to_string(),
            diagnostics: Vec::new(),
        })?;
        let script = &materialized.path;
        let tsconfig = config.tsconfig.as_ref().map(|path| canonical_path(path));
        let tsconfig_digest = tsconfig
            .as_ref()
            .and_then(|path| fs::read(path).ok().map(|content| digest_bytes(&content)));
        let helper_digest = materialized.digest;
        let request = HelperRequest {
            schema_version: HELPER_PROTOCOL_VERSION,
            root: canonical_path(&config.root),
            tsconfig,
            tsconfig_digest,
            typescript_package: config
                .typescript_package
                .clone()
                .map(|path| canonical_path(&path)),
            expected_compiler_version: config.expected_compiler_version.clone(),
            helper_digest,
            dependency_whitelist: config.dependency_whitelist.clone(),
            files: snapshots
                .values()
                .map(|item| HelperSource {
                    path: item.path.clone(),
                    content: item.source.clone(),
                    digest: item.digest.clone(),
                })
                .collect(),
        };
        let input = serde_json::to_vec(&request).map_err(|error| ProjectContextError {
            code: "JS_CONTEXT_REQUEST".to_owned(),
            message: error.to_string(),
            diagnostics: Vec::new(),
        })?;
        let output = invoke_helper(config, script, &input)?;
        if output.len() > config.max_output_bytes {
            return Err(ProjectContextError {
                code: "JS_CONTEXT_OUTPUT_LIMIT".to_owned(),
                message: format!(
                    "TypeScript helper output exceeds {} bytes",
                    config.max_output_bytes
                ),
                diagnostics: Vec::new(),
            });
        }
        let mut response: HelperResponse =
            serde_json::from_slice(&output).map_err(|error| ProjectContextError {
                code: "JS_CONTEXT_RESPONSE".to_owned(),
                message: format!("invalid TypeScript helper response: {error}"),
                diagnostics: Vec::new(),
            })?;
        if response.schema_version != HELPER_PROTOCOL_VERSION {
            return Err(ProjectContextError {
                code: "JS_CONTEXT_PROTOCOL".to_owned(),
                message: format!("unsupported helper schema {}", response.schema_version),
                diagnostics: Vec::new(),
            });
        }
        diagnostics.extend(std::mem::take(&mut response.diagnostics));
        validate_response_metadata(
            &response,
            &config.expected_compiler_version,
            &mut diagnostics,
        );
        let files = std::mem::take(&mut response.files);
        let facts = collect_helper_facts(files, &snapshots, &mut diagnostics);
        let fingerprint = helper_fingerprint(&mut response, &input, &mut diagnostics);
        let status =
            if response.complete && !diagnostics.iter().any(|item| item.category == "error") {
                ProjectSemanticStatus::Complete
            } else {
                ProjectSemanticStatus::Incomplete
            };
        Ok(Self {
            config: config.clone(),
            status,
            fingerprint,
            compiler_version: response.compiler_version,
            compiler_path: response.compiler_path,
            files: facts,
            dependencies: response.dependencies,
            diagnostics,
        })
    }

    fn incomplete(
        config: TypeScriptProjectConfig,
        diagnostics: Vec<SemanticDiagnostic>,
        why: &str,
    ) -> Self {
        Self {
            config,
            status: ProjectSemanticStatus::Incomplete,
            fingerprint: digest_bytes(why.as_bytes()),
            compiler_version: None,
            compiler_path: None,
            files: BTreeMap::new(),
            dependencies: Vec::new(),
            diagnostics,
        }
    }

    #[must_use]
    pub fn status(&self) -> ProjectSemanticStatus {
        self.status
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.status == ProjectSemanticStatus::Complete
    }

    #[must_use]
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    #[must_use]
    pub fn compiler_version(&self) -> Option<&str> {
        self.compiler_version.as_deref()
    }

    #[must_use]
    pub fn compiler_path(&self) -> Option<&Path> {
        self.compiler_path.as_deref()
    }

    #[must_use]
    pub fn diagnostics(&self) -> &[SemanticDiagnostic] {
        &self.diagnostics
    }

    #[must_use]
    pub fn dependencies(&self) -> &[SemanticDependency] {
        &self.dependencies
    }

    #[must_use = "iterate over the loaded source paths"]
    pub fn source_paths(&self) -> impl Iterator<Item = &Path> {
        self.files.keys().map(PathBuf::as_path)
    }

    #[must_use]
    pub fn file_facts(&self, path: &Path) -> Option<&SemanticFileFacts> {
        self.files.get(&canonical_path(path))
    }

    /// Runs ordinary Oxc rules and then adds compiler-backed semantic rules.
    /// A source not present in the loaded snapshots, or an incomplete context,
    /// returns the ordinary report plus explicit diagnostics and no semantic
    /// findings.
    #[must_use]
    pub fn analyze_with_context(
        &self,
        path: PathBuf,
        source: &str,
        language: JstsLanguage,
        options: &AnalyzerOptions,
    ) -> SemanticAnalysis {
        let ordinary_path = path.clone();
        let ordinary = move || crate::analyze(ordinary_path, source, language, options);
        let mut diagnostics = self.diagnostics.clone();
        let canonical = canonical_path(&path);
        let digest = digest_bytes(source.as_bytes());
        if self.status != ProjectSemanticStatus::Complete {
            diagnostics.push(SemanticDiagnostic {
                code: "JS_CONTEXT_INCOMPLETE".to_owned(),
                message:
                    "Semantic rules are unavailable because compiler/project context is incomplete."
                        .to_owned(),
                category: "error".to_owned(),
                path: Some(canonical),
                start: None,
                end: None,
            });
            return SemanticAnalysis {
                report: ordinary(),
                diagnostics,
            };
        }
        let Some(expected) = self.files.get(&canonical) else {
            diagnostics.push(SemanticDiagnostic {
                code: "JS_CONTEXT_SOURCE_NOT_LOADED".to_owned(),
                message: format!(
                    "Source was not part of the loaded project snapshot: {}",
                    canonical.display()
                ),
                category: "error".to_owned(),
                path: Some(canonical),
                start: None,
                end: None,
            });
            return SemanticAnalysis {
                report: ordinary(),
                diagnostics,
            };
        };
        if expected.source_digest != digest {
            diagnostics.push(SemanticDiagnostic {
                code: "JS_CONTEXT_SOURCE_CHANGED".to_owned(),
                message: "Source differs from the snapshot used by the compiler helper.".to_owned(),
                category: "error".to_owned(),
                path: Some(canonical),
                start: None,
                end: None,
            });
            return SemanticAnalysis {
                report: ordinary(),
                diagnostics,
            };
        }
        let mut report = crate::analyze_with_facts(path, source, language, options, Some(expected));
        report.issues.extend(semantic_context::run(
            expected,
            source,
            language,
            &self.config.dependency_whitelist,
        ));
        sort_issues(&mut report.issues);
        SemanticAnalysis {
            report,
            diagnostics,
        }
    }

    /// Compatibility convenience for CLI callers whose language was already
    /// selected by the project file router.
    #[must_use]
    pub fn analyze(
        &self,
        path: PathBuf,
        source: &str,
        options: &AnalyzerOptions,
    ) -> SemanticAnalysis {
        let name = path.to_string_lossy().to_ascii_lowercase();
        let language = if [".ts", ".tsx", ".mts", ".cts", ".d.ts"]
            .iter()
            .any(|extension| name.ends_with(*extension))
        {
            JstsLanguage::TypeScript
        } else {
            JstsLanguage::JavaScript
        };
        self.analyze_with_context(path, source, language, options)
    }

    /// Free-function-shaped convenience API for callers that retain a context
    /// object but prefer not to call an inherent method.
    #[must_use]
    pub fn config(&self) -> &TypeScriptProjectConfig {
        &self.config
    }
}

/// Convenience wrapper matching the project API wording used by CLI callers.
#[must_use]
pub fn analyze_with_context(
    context: &ProjectSemanticContext,
    path: PathBuf,
    source: &str,
    language: JstsLanguage,
    options: &AnalyzerOptions,
) -> SemanticAnalysis {
    context.analyze_with_context(path, source, language, options)
}

#[derive(Debug, Serialize)]
struct HelperRequest {
    schema_version: u32,
    root: PathBuf,
    #[serde(skip_serializing_if = "Option::is_none")]
    tsconfig: Option<PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    tsconfig_digest: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    typescript_package: Option<PathBuf>,
    expected_compiler_version: String,
    helper_digest: String,
    dependency_whitelist: Vec<String>,
    files: Vec<HelperSource>,
}

#[derive(Debug, Serialize)]
struct HelperSource {
    path: PathBuf,
    content: String,
    digest: String,
}

#[derive(Debug, Deserialize)]
struct HelperResponse {
    schema_version: u32,
    #[serde(default)]
    complete: bool,
    #[serde(default)]
    compiler_version: Option<String>,
    #[serde(default)]
    compiler_path: Option<PathBuf>,
    #[serde(default)]
    files: Vec<SemanticFileFacts>,
    #[serde(default)]
    dependencies: Vec<SemanticDependency>,
    #[serde(default)]
    diagnostics: Vec<SemanticDiagnostic>,
    #[serde(default)]
    fingerprint: String,
}

#[derive(Debug)]
struct MaterializedHelper {
    path: PathBuf,
    digest: String,
}

fn materialize_helper(
    config: &TypeScriptProjectConfig,
) -> Result<MaterializedHelper, std::io::Error> {
    if let Some(path) = &config.helper_script {
        let path = canonical_path(path);
        let digest = fs::read(&path).map_or_else(
            |_| digest_bytes(EMBEDDED_HELPER.as_bytes()),
            |content| digest_bytes(&content),
        );
        return Ok(MaterializedHelper { path, digest });
    }
    publish_embedded_helper(config)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn publish_embedded_helper(
    _config: &TypeScriptProjectConfig,
) -> Result<MaterializedHelper, std::io::Error> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "secure compiler-helper materialization is unsupported on this platform",
    ))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn publish_embedded_helper(
    config: &TypeScriptProjectConfig,
) -> Result<MaterializedHelper, std::io::Error> {
    let display_path = config
        .helper_cache_dir
        .join(secure_cache::helper_file_name());
    let dir = secure_cache::open_cache_dir_anchored(&config.root, &config.helper_cache_dir)?;
    let (path, digest) = secure_cache::publish_helper_into(&dir, &display_path)?;
    Ok(MaterializedHelper { path, digest })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod secure_cache {
    use super::{EMBEDDED_HELPER, HELPER_PROTOCOL_VERSION, digest_bytes};
    use rustix::fs::{
        AtFlags, FileType, Mode, OFlags, fstat, fsync, mkdirat, openat, renameat, statat, unlinkat,
    };
    use rustix::io::Errno;
    use rustix::process::geteuid;
    use std::ffi::OsStr;
    use std::fs::File;
    use std::io::{Error as IoError, Read, Write};
    use std::os::fd::OwnedFd;
    use std::path::{Component, Path, PathBuf};

    fn symlink_refusal(path: &Path) -> IoError {
        IoError::other(format!(
            "refusing to materialize the TypeScript helper through symbolic link {}",
            path.to_string_lossy().escape_debug()
        ))
    }

    pub(super) fn helper_file_name() -> String {
        format!("semantic-helper-v{HELPER_PROTOCOL_VERSION}.cjs")
    }

    fn dir_flags() -> OFlags {
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC
    }

    /// A symlinked path component opened with `O_NOFOLLOW | O_DIRECTORY`
    /// reports `ENOTDIR` on Linux (the directory check precedes the
    /// `ELOOP` check), so `ENOTDIR` must be confirmed against the component
    /// itself before it can be reported as a symbolic-link refusal.
    fn is_symlink_component(parent: &OwnedFd, name: &OsStr) -> bool {
        statat(parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .is_ok_and(|stat| FileType::from_raw_mode(stat.st_mode) == FileType::Symlink)
    }

    fn open_dir_component(
        parent: &OwnedFd,
        name: &OsStr,
        create: bool,
    ) -> std::io::Result<OwnedFd> {
        match openat(parent, name, dir_flags(), Mode::empty()) {
            Ok(fd) => Ok(fd),
            Err(Errno::NOENT) if create => {
                match mkdirat(parent, name, Mode::from_raw_mode(0o700)) {
                    Ok(()) | Err(Errno::EXIST) => {}
                    Err(error) => return Err(IoError::from(error)),
                }
                match openat(parent, name, dir_flags(), Mode::empty()) {
                    Ok(fd) => Ok(fd),
                    Err(Errno::LOOP | Errno::MLINK) => Err(symlink_refusal(Path::new(name))),
                    Err(Errno::NOTDIR) if is_symlink_component(parent, name) => {
                        Err(symlink_refusal(Path::new(name)))
                    }
                    Err(error) => Err(IoError::from(error)),
                }
            }
            Err(Errno::LOOP | Errno::MLINK) => Err(symlink_refusal(Path::new(name))),
            Err(Errno::NOTDIR) if is_symlink_component(parent, name) => {
                Err(symlink_refusal(Path::new(name)))
            }
            Err(error) => Err(IoError::from(error)),
        }
    }

    /// The cache path is never canonicalized: each component is opened or
    /// created relative to its parent descriptor with `O_NOFOLLOW`.
    ///
    /// Explicit cache paths are supported both below and outside the project
    /// root.  Existing path components are not chmodded; newly created
    /// directories request the private `0o700` mode subject to the umask.
    pub(super) fn open_cache_dir_anchored(
        _root: &Path,
        cache_dir: &Path,
    ) -> std::io::Result<OwnedFd> {
        let mut current = if cache_dir.is_absolute() {
            openat(rustix::fs::CWD, Path::new("/"), dir_flags(), Mode::empty())
        } else {
            openat(rustix::fs::CWD, Path::new("."), dir_flags(), Mode::empty())
        }
        .map_err(IoError::from)?;
        let mut moved = false;
        for component in cache_dir.components() {
            match component {
                Component::Normal(name) => {
                    let next = open_dir_component(&current, name, true)?;
                    current = next;
                    moved = true;
                }
                Component::CurDir | Component::RootDir => {}
                Component::ParentDir => {
                    current = openat(&current, OsStr::new(".."), dir_flags(), Mode::empty())
                        .map_err(IoError::from)?;
                    moved = true;
                }
                Component::Prefix(_) => {
                    return Err(IoError::new(
                        std::io::ErrorKind::InvalidInput,
                        "TypeScript helper cache contains an unsupported path component",
                    ));
                }
            }
        }
        if !moved {
            return Err(IoError::new(
                std::io::ErrorKind::InvalidInput,
                "the TypeScript helper cache must name a dedicated directory",
            ));
        }
        let stat = fstat(&current).map_err(IoError::from)?;
        if stat.st_uid != geteuid().as_raw() {
            return Err(IoError::new(
                std::io::ErrorKind::PermissionDenied,
                "TypeScript helper cache directory is not owned by the effective user",
            ));
        }
        Ok(current)
    }

    fn read_regular_nofollow(
        dir: &OwnedFd,
        name: &OsStr,
        display: &Path,
    ) -> std::io::Result<Option<Vec<u8>>> {
        let fd = match openat(
            dir,
            name,
            OFlags::RDONLY | OFlags::NONBLOCK | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        ) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(Errno::LOOP | Errno::MLINK) => {
                return Err(symlink_refusal(display));
            }
            Err(error) => return Err(IoError::from(error)),
        };
        let stat = fstat(&fd).map_err(IoError::from)?;
        if stat.st_uid != geteuid().as_raw() {
            return Err(IoError::new(
                std::io::ErrorKind::PermissionDenied,
                "TypeScript helper cache entry is not owned by the effective user",
            ));
        }
        if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
            return Err(IoError::new(
                std::io::ErrorKind::InvalidData,
                "TypeScript helper cache entry is not a regular file",
            ));
        }
        let handle = File::from(fd);
        let mut content = Vec::with_capacity(EMBEDDED_HELPER.len() + 1);
        handle
            .take((EMBEDDED_HELPER.len() + 1) as u64)
            .read_to_end(&mut content)?;
        Ok(Some(content))
    }

    pub(super) fn publish_helper_into(
        dir: &OwnedFd,
        display_path: &Path,
    ) -> std::io::Result<(PathBuf, String)> {
        let pinned = EMBEDDED_HELPER.as_bytes();
        let name = helper_file_name();
        if let Some(existing) = read_regular_nofollow(dir, OsStr::new(&name), display_path)?
            && existing == pinned
        {
            return Ok((display_path.to_path_buf(), digest_bytes(pinned)));
        }
        let mut published = false;
        for attempt in 0..64_u32 {
            let temporary_name = format!(".{name}.tmp-{}-{attempt}", std::process::id());
            let fd = match openat(
                dir,
                OsStr::new(&temporary_name),
                OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::from_raw_mode(0o644),
            ) {
                Ok(fd) => fd,
                Err(Errno::EXIST) => continue,
                Err(error) => return Err(IoError::from(error)),
            };
            if let Err(error) = write_and_sync(fd, pinned) {
                let _ = unlinkat(dir, OsStr::new(&temporary_name), AtFlags::empty());
                return Err(error);
            }
            if let Err(error) = renameat(dir, OsStr::new(&temporary_name), dir, OsStr::new(&name)) {
                let _ = unlinkat(dir, OsStr::new(&temporary_name), AtFlags::empty());
                return Err(IoError::from(error));
            }
            published = true;
            break;
        }
        if !published {
            return Err(IoError::other(
                "no free temporary name while publishing the TypeScript helper",
            ));
        }
        fsync(dir).map_err(IoError::from)?;
        let proof =
            read_regular_nofollow(dir, OsStr::new(&name), display_path)?.ok_or_else(|| {
                IoError::other("published TypeScript helper disappeared before verification")
            })?;
        if proof != pinned {
            return Err(IoError::other(
                "published TypeScript helper content identity mismatch",
            ));
        }
        Ok((display_path.to_path_buf(), digest_bytes(pinned)))
    }

    fn write_and_sync(fd: OwnedFd, bytes: &[u8]) -> std::io::Result<()> {
        let mut handle = File::from(fd);
        handle.write_all(bytes)?;
        handle.flush()?;
        fsync(&handle).map_err(IoError::from)
    }
}
const EMBEDDED_HELPER_BOOTSTRAP: &str = r"
const Module = require('node:module');
const path = require('node:path');
const filename = process.argv[1];
const countText = process.env.HOONARQUBE_EMBEDDED_HELPER_CHUNK_COUNT;
const count = Number.parseInt(countText || '', 10);
if (!filename || !Number.isSafeInteger(count) || count < 1) {
  throw new Error('embedded TypeScript helper source is unavailable');
}
const chunks = [];
for (let index = 0; index < count; index += 1) {
  const chunk = process.env[`HOONARQUBE_EMBEDDED_HELPER_CHUNK_${index}`];
  if (typeof chunk !== 'string') {
    throw new Error('embedded TypeScript helper source is incomplete');
  }
  chunks.push(chunk);
}
const source = chunks.join('');
const helper = new Module(filename, require.main);
helper.filename = filename;
helper.paths = Module._nodeModulePaths(path.dirname(filename));
require.main = helper;
helper._compile(source, filename);
";

const EMBEDDED_HELPER_ENV_CHUNK_BYTES: usize = 32 * 1024;

fn embedded_helper_chunks(source: &str) -> impl Iterator<Item = &str> {
    let mut start = 0;
    std::iter::from_fn(move || {
        if start == source.len() {
            return None;
        }
        let mut end = (start + EMBEDDED_HELPER_ENV_CHUNK_BYTES).min(source.len());
        while end > start && !source.is_char_boundary(end) {
            end -= 1;
        }
        let chunk = &source[start..end];
        start = end;
        Some(chunk)
    })
}

fn invoke_helper(
    config: &TypeScriptProjectConfig,
    script: &Path,
    input: &[u8],
) -> Result<Vec<u8>, ProjectContextError> {
    let mut command = Command::new(&config.helper_program);
    command.args(&config.helper_args);
    if config.helper_script.is_none() {
        command.arg("-e").arg(EMBEDDED_HELPER_BOOTSTRAP).arg(script);
        let mut chunk_count = 0;
        for (index, chunk) in embedded_helper_chunks(EMBEDDED_HELPER).enumerate() {
            command.env(format!("HOONARQUBE_EMBEDDED_HELPER_CHUNK_{index}"), chunk);
            chunk_count += 1;
        }
        command.env(
            "HOONARQUBE_EMBEDDED_HELPER_CHUNK_COUNT",
            chunk_count.to_string(),
        );
    } else {
        command.arg(script);
    }
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|error| ProjectContextError {
        code: "JS_CONTEXT_HELPER_SPAWN".to_owned(),
        message: error.to_string(),
        diagnostics: Vec::new(),
    })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input)
            .map_err(|error| ProjectContextError {
                code: "JS_CONTEXT_HELPER_STDIN".to_owned(),
                message: error.to_string(),
                diagnostics: Vec::new(),
            })?;
    }
    let stdout = child.stdout.take().ok_or_else(|| ProjectContextError {
        code: "JS_CONTEXT_HELPER_STDOUT".to_owned(),
        message: "helper stdout was not captured".to_owned(),
        diagnostics: Vec::new(),
    })?;
    let stderr = child.stderr.take().ok_or_else(|| ProjectContextError {
        code: "JS_CONTEXT_HELPER_STDERR".to_owned(),
        message: "helper stderr was not captured".to_owned(),
        diagnostics: Vec::new(),
    })?;
    let limit = config.max_output_bytes;
    let stdout_reader = std::thread::spawn(move || read_capped(stdout, limit));
    let stderr_reader = std::thread::spawn(move || read_capped(stderr, limit));
    let status = child.wait().map_err(|error| ProjectContextError {
        code: "JS_CONTEXT_HELPER_WAIT".to_owned(),
        message: error.to_string(),
        diagnostics: Vec::new(),
    })?;
    let (stdout, stdout_overflow) = stdout_reader
        .join()
        .map_err(|_| ProjectContextError {
            code: "JS_CONTEXT_HELPER_STDOUT".to_owned(),
            message: "helper stdout reader panicked".to_owned(),
            diagnostics: Vec::new(),
        })?
        .map_err(|error| ProjectContextError {
            code: "JS_CONTEXT_HELPER_STDOUT".to_owned(),
            message: error.to_string(),
            diagnostics: Vec::new(),
        })?;
    let (stderr, stderr_overflow) = stderr_reader
        .join()
        .map_err(|_| ProjectContextError {
            code: "JS_CONTEXT_HELPER_STDERR".to_owned(),
            message: "helper stderr reader panicked".to_owned(),
            diagnostics: Vec::new(),
        })?
        .map_err(|error| ProjectContextError {
            code: "JS_CONTEXT_HELPER_STDERR".to_owned(),
            message: error.to_string(),
            diagnostics: Vec::new(),
        })?;
    if stdout_overflow || stderr_overflow {
        return Err(ProjectContextError {
            code: "JS_CONTEXT_OUTPUT_LIMIT".to_owned(),
            message: format!("TypeScript helper output exceeds {limit} bytes"),
            diagnostics: Vec::new(),
        });
    }
    if !status.success() {
        let stderr = String::from_utf8_lossy(&stderr);
        return Err(ProjectContextError {
            code: "JS_CONTEXT_HELPER_EXIT".to_owned(),
            message: format!("helper exited with {status}: {}", stderr.trim()),
            diagnostics: Vec::new(),
        });
    }
    Ok(stdout)
}

fn read_capped<R: Read>(mut reader: R, limit: usize) -> std::io::Result<(Vec<u8>, bool)> {
    let mut retained = Vec::new();
    let mut buffer = vec![0_u8; 32 * 1024].into_boxed_slice();
    let mut overflow = false;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        if retained.len() < limit {
            let keep = (limit - retained.len()).min(count);
            retained.extend_from_slice(&buffer[..keep]);
            if keep < count {
                overflow = true;
            }
        } else {
            overflow = true;
        }
    }
    Ok((retained, overflow))
}

fn digest_bytes(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(char::from(HEX[(byte >> 4) as usize]));
        output.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    output
}
fn is_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
fn canonical_path(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| {
        if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir().map_or_else(|_| path.to_path_buf(), |cwd| cwd.join(path))
        }
    })
}

#[cfg(test)]
mod materialization_tests {
    use super::*;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    use std::os::unix::fs::PermissionsExt;

    struct ScenarioRoot {
        root: PathBuf,
    }

    impl ScenarioRoot {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("hoonarqube-issue98-{name}-{}", std::process::id()));
            let _ = fs::remove_dir_all(&root);
            fs::create_dir_all(&root).expect("scenario root");
            Self { root }
        }

        fn config(&self) -> TypeScriptProjectConfig {
            let project = self.root.join("project");
            fs::create_dir_all(&project).expect("project directory");
            TypeScriptProjectConfig::new(project)
        }
    }

    impl Drop for ScenarioRoot {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn helper_path(config: &TypeScriptProjectConfig) -> PathBuf {
        config
            .helper_cache_dir
            .join(format!("semantic-helper-v{HELPER_PROTOCOL_VERSION}.cjs"))
    }

    fn helper_never_started(scenario: &ScenarioRoot) -> PathBuf {
        scenario.root.join("helper-program-does-not-exist")
    }

    fn load_without_helper(
        mut config: TypeScriptProjectConfig,
        scenario: &ScenarioRoot,
    ) -> Result<ProjectSemanticContext, ProjectContextError> {
        config.helper_program = helper_never_started(scenario);
        ProjectSemanticContext::load(&config, &ProjectSemanticSources::default())
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn publishes_and_reuses_pinned_helper() {
        let scenario = ScenarioRoot::new("normal");
        let config = scenario.config();
        let path = helper_path(&config);
        let _ = load_without_helper(config.clone(), &scenario);
        assert_eq!(
            fs::metadata(&config.helper_cache_dir)
                .expect("cache metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        assert!(
            path.is_file() && !path.is_symlink(),
            "normal materialization must publish a regular helper"
        );
        assert_eq!(fs::read(&path).expect("helper"), EMBEDDED_HELPER.as_bytes());
        fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
            .expect("permissions");
        let _ = load_without_helper(config, &scenario);
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o600
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn preserves_existing_cache_ancestor_permissions() {
        let scenario = ScenarioRoot::new("existing-directory-mode");
        let config = scenario.config();
        let source_dir = config.root.join("src");
        fs::create_dir_all(&source_dir).expect("source directory");
        fs::set_permissions(
            &source_dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("source permissions");
        let cache_dir = source_dir.join("cache");
        fs::create_dir_all(&cache_dir).expect("existing cache directory");
        fs::set_permissions(
            &cache_dir,
            std::os::unix::fs::PermissionsExt::from_mode(0o755),
        )
        .expect("cache permissions");
        let mut custom = config;
        custom.helper_cache_dir = cache_dir;
        let _ = load_without_helper(custom.clone(), &scenario);
        assert_eq!(
            fs::metadata(&source_dir)
                .expect("source metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "existing cache ancestors must not be chmodded"
        );
        assert_eq!(
            fs::metadata(&custom.helper_cache_dir)
                .expect("cache metadata")
                .permissions()
                .mode()
                & 0o777,
            0o755,
            "existing cache directories must not be chmodded"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn supports_explicit_external_cache_path() {
        let scenario = ScenarioRoot::new("external-cache");
        let mut config = scenario.config();
        config.helper_cache_dir = scenario.root.join("external-cache");
        let path = helper_path(&config);
        let _ = load_without_helper(config, &scenario);
        assert!(
            path.is_file() && !path.is_symlink(),
            "explicit external cache must remain supported"
        );
        assert_eq!(fs::read(&path).expect("helper"), EMBEDDED_HELPER.as_bytes());
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn rejects_final_symlink_without_sentinel_write() {
        let scenario = ScenarioRoot::new("final-symlink");
        let config = scenario.config();
        fs::create_dir_all(&config.helper_cache_dir).expect("cache");
        let sentinel = scenario.root.join("sentinel");
        fs::write(&sentinel, b"unchanged").expect("sentinel");
        let path = helper_path(&config);
        std::os::unix::fs::symlink(&sentinel, &path).expect("symlink");
        let error = load_without_helper(config, &scenario)
            .expect_err("final symlink must stop before helper invocation");
        assert_eq!(error.code, "JS_CONTEXT_HELPER_PREPARE");
        assert!(error.message.contains("symbolic link"));
        assert_eq!(fs::read(&sentinel).expect("sentinel"), b"unchanged");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn rejects_parent_symlink_without_outside_write() {
        let scenario = ScenarioRoot::new("parent-link");
        let config = scenario.config();
        let outside = scenario.root.join("outside");
        fs::create_dir_all(&outside).expect("outside");
        let hoonarqube = config.helper_cache_dir.parent().unwrap().parent().unwrap();
        fs::create_dir_all(hoonarqube).expect("cache parent");
        std::os::unix::fs::symlink(&outside, hoonarqube.join("semantic")).expect("parent link");
        let error = load_without_helper(config, &scenario)
            .expect_err("parent symlink must stop before helper invocation");
        assert_eq!(error.code, "JS_CONTEXT_HELPER_PREPARE");
        assert!(error.message.contains("symbolic link"));
        assert!(
            fs::read_dir(outside)
                .expect("outside listing")
                .next()
                .is_none()
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn controlled_final_swap_is_rejected_without_sentinel_write() {
        let scenario = ScenarioRoot::new("controlled-swap");
        let config = scenario.config();
        let path = helper_path(&config);
        let _ = load_without_helper(config.clone(), &scenario);
        assert!(path.is_file() && !path.is_symlink());
        let sentinel = scenario.root.join("sentinel");
        fs::write(&sentinel, b"unchanged").expect("sentinel");
        fs::remove_file(&path).expect("published helper");
        std::os::unix::fs::symlink(&sentinel, &path).expect("swap");
        let error = load_without_helper(config, &scenario).expect_err("swapped symlink");
        assert_eq!(error.code, "JS_CONTEXT_HELPER_PREPARE");
        assert!(error.message.contains("symbolic link"));
        assert_eq!(fs::read(&sentinel).expect("sentinel"), b"unchanged");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn replaces_untrusted_cached_content() {
        let scenario = ScenarioRoot::new("untrusted");
        let config = scenario.config();
        fs::create_dir_all(&config.helper_cache_dir).expect("cache");
        let path = helper_path(&config);
        fs::write(&path, b"untrusted").expect("cache entry");
        let _ = load_without_helper(config.clone(), &scenario);
        assert_eq!(fs::read(&path).expect("helper"), EMBEDDED_HELPER.as_bytes());
        assert_eq!(
            fs::read_dir(&config.helper_cache_dir)
                .expect("cache listing")
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp-"))
                .count(),
            0
        );
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[test]
    fn unsupported_platform_fails_closed() {
        let scenario = ScenarioRoot::new("unsupported");
        let error =
            ProjectSemanticContext::load(&scenario.config(), &ProjectSemanticSources::default())
                .expect_err("unsupported");
        assert_eq!(error.code, "JS_CONTEXT_HELPER_PREPARE");
        assert!(error.message.contains("unsupported"));
    }
}
