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

        let script = materialize_helper(config).map_err(|error| ProjectContextError {
            code: "JS_CONTEXT_HELPER_PREPARE".to_owned(),
            message: error.to_string(),
            diagnostics: Vec::new(),
        })?;
        let tsconfig = config.tsconfig.as_ref().map(|path| canonical_path(path));
        let tsconfig_digest = tsconfig
            .as_ref()
            .and_then(|path| fs::read(path).ok().map(|content| digest_bytes(&content)));
        let helper_digest = fs::read(&script).map_or_else(
            |_| digest_bytes(EMBEDDED_HELPER.as_bytes()),
            |content| digest_bytes(&content),
        );
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
        let output = invoke_helper(config, &script, &input)?;
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

fn materialize_helper(config: &TypeScriptProjectConfig) -> Result<PathBuf, std::io::Error> {
    if let Some(path) = &config.helper_script {
        return Ok(canonical_path(path));
    }
    fs::create_dir_all(&config.helper_cache_dir)?;
    let path = config
        .helper_cache_dir
        .join(format!("semantic-helper-v{HELPER_PROTOCOL_VERSION}.cjs"));
    let needs_write = fs::read_to_string(&path).map_or(true, |current| current != EMBEDDED_HELPER);
    if needs_write {
        fs::write(&path, EMBEDDED_HELPER.as_bytes())?;
    }
    Ok(path)
}

fn invoke_helper(
    config: &TypeScriptProjectConfig,
    script: &Path,
    input: &[u8],
) -> Result<Vec<u8>, ProjectContextError> {
    let mut command = Command::new(&config.helper_program);
    command.args(&config.helper_args).arg(script);
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
