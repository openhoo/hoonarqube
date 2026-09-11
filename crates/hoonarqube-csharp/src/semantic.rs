//! Optional compiler-backed C# project semantics.
//!
//! The normal [`crate::analyze`] entry point intentionally remains a standalone
//! tree-sitter analyzer.  This module is an additive, explicit opt-in boundary:
//! one trusted helper invocation receives the same source snapshots as the
//! caller and returns schema-versioned Roslyn facts.  Rules consume only facts
//! whose source/project/compiler manifest has been verified.  A missing helper,
//! failed project evaluation, stale snapshot, unresolved reference, or protocol
//! mismatch is represented as [`SemanticStatus::Incomplete`] and therefore
//! produces no semantic false positives.

use std::collections::{BTreeMap, BTreeSet};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::{AnalyzerOptions, CsLanguage, cst};

/// Current wire format understood by the Rust loader and the checked-in helper.
pub const SEMANTIC_SCHEMA_VERSION: u32 = 2;

/// Source text supplied to the helper.  The helper MUST compile this exact
/// snapshot rather than silently reopening a changed file on disk.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSnapshot {
    pub path: PathBuf,
    pub source: String,
    pub content_digest: String,
    /// Optional owning project.  Empty means the configured root project.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub project: Option<PathBuf>,
}

impl SourceSnapshot {
    #[must_use]
    pub fn new(path: PathBuf, source: impl Into<String>) -> Self {
        let source = source.into();
        Self {
            content_digest: digest_bytes(source.as_bytes()),
            path,
            source,
            project: None,
        }
    }

    #[must_use]
    pub fn with_project(mut self, project: PathBuf) -> Self {
        self.project = Some(project);
        self
    }

    #[must_use]
    pub fn digest_matches(&self) -> bool {
        self.content_digest == digest_bytes(self.source.as_bytes())
    }
}

/// How nullable analysis is configured for the compiler invocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum NullableMode {
    Disable,
    #[default]
    Enable,
    Warnings,
    Annotations,
}

/// An executable and fixed argument prefix for the semantic helper.  It is
/// intentionally not a shell command: no shell interpolation or hidden
/// runtime download is performed by the Rust analyzer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelperCommand {
    pub program: PathBuf,
    #[serde(default)]
    pub args: Vec<String>,
}

/// Explicit project/compiler trust and rule configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectSemanticConfig {
    pub project: PathBuf,
    pub helper: Option<HelperCommand>,
    /// Project evaluation and reference loading are opt-in.  `false` always
    /// yields a structured incomplete context and never syntax-only guesses.
    pub trusted_evaluation: bool,
    /// If true, the helper may run a bounded `dotnet build --no-restore` to
    /// materialize project references and Razor generated sources.
    pub trusted_build: bool,
    pub target_framework: Option<String>,
    #[serde(default)]
    pub defines: Vec<String>,
    pub language_version: Option<String>,
    pub nullable: NullableMode,
    /// Maximum helper wall-clock duration in milliseconds.
    pub timeout_ms: u64,
    /// Maximum combined helper stdout/stderr retained in memory.
    pub max_output_bytes: usize,
    pub rules: SemanticRuleOptions,
    /// Enable generated Razor source inspection and source-map projection.
    pub include_razor_generated: bool,
}

impl Default for ProjectSemanticConfig {
    fn default() -> Self {
        Self {
            project: PathBuf::new(),
            helper: None,
            trusted_evaluation: false,
            trusted_build: false,
            target_framework: None,
            defines: Vec::new(),
            language_version: None,
            nullable: NullableMode::Enable,
            timeout_ms: 30_000,
            max_output_bytes: 16 * 1024 * 1024,
            rules: SemanticRuleOptions::default(),
            include_razor_generated: false,
        }
    }
}
/// Source strings used for deterministic offline helper preparation.  The
/// preparation function copies these exact bytes into an owned cache before
/// invoking the installed SDK; it never downloads a runtime or package.
pub const BUNDLED_HELPER_PROJECT: &str =
    include_str!("../../../tools/semantic/csharp/CSharpSemanticHelper.csproj");
pub const BUNDLED_HELPER_PROGRAM: &str = include_str!("../../../tools/semantic/csharp/Program.cs");
pub const BUNDLED_HELPER_QUICKFIX_PLANNER: &str =
    include_str!("../../../tools/semantic/csharp/QuickFixPlanner.cs");
pub const BUNDLED_HELPER_RAZOR_SOURCE_FACTS: &str =
    include_str!("../../../tools/semantic/csharp/RazorSourceFacts.cs");
pub const BUNDLED_HELPER_NUGET_CONFIG: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSources>
    <clear />
  </packageSources>
</configuration>
"#;
/// Cache namespace for the lock-and-marker lifecycle below.  Older binaries
/// use `csharp-semantic` directly and do not understand this protocol, so a
/// new namespace keeps them from rewriting bundles prepared by this code.
const BUNDLED_HELPER_CACHE_NAMESPACE: &str = "csharp-semantic-v2";
const BUNDLED_HELPER_BUILD_LOCK: &str = ".build.lock";
const BUNDLED_HELPER_READY_MARKER: &str = ".complete";
const BUNDLED_HELPER_READY_MARKER_TEMP: &str = ".complete.tmp";

/// Prepares the checked-in helper in an owned content-addressed cache using an
/// already installed `dotnet` SDK.  Callers may pass the returned
/// [`HelperCommand`] into [`ProjectSemanticConfig::helper`].  A missing SDK or
/// failed offline build is an explicit error, never a syntax-only fallback.
///
/// # Errors
///
/// Returns a diagnostic if the SDK cannot be queried, helper sources cannot be
/// cached, offline restore/build fails, or the expected helper is not produced.
pub fn prepare_bundled_helper(cache_root: &Path) -> Result<HelperCommand, SemanticDiagnostic> {
    let dotnet = std::env::var_os("HOONARQUBE_DOTNET")
        .map_or_else(|| PathBuf::from("dotnet"), PathBuf::from);
    let directory = bundled_helper_directory(cache_root, &dotnet)?;
    if bundled_helper_ready(&directory) {
        return Ok(HelperCommand {
            program: dotnet.clone(),
            args: vec![
                bundled_helper_dll(&directory)
                    .to_string_lossy()
                    .into_owned(),
            ],
        });
    }

    let _build_lock = lock_bundled_helper(&directory)?;
    if bundled_helper_ready(&directory) {
        return Ok(HelperCommand {
            program: dotnet.clone(),
            args: vec![
                bundled_helper_dll(&directory)
                    .to_string_lossy()
                    .into_owned(),
            ],
        });
    }

    let (project, nuget_config) = write_bundled_helper_sources(&directory)?;
    let dll = build_bundled_helper(&dotnet, &directory, &project, &nuget_config)?;
    publish_bundled_helper(&directory)?;
    Ok(HelperCommand {
        program: dotnet,
        args: vec![dll.to_string_lossy().into_owned()],
    })
}

fn bundled_helper_directory(
    cache_root: &Path,
    dotnet: &Path,
) -> Result<PathBuf, SemanticDiagnostic> {
    let version = Command::new(dotnet)
        .arg("--version")
        .output()
        .map_err(|error| {
            diag(
                "dotnet_missing",
                format!("could not execute dotnet SDK: {error}"),
                None,
            )
        })?;
    if !version.status.success() {
        return Err(diag(
            "dotnet_missing",
            "installed dotnet SDK is unavailable",
            None,
        ));
    }
    let sdk_version = String::from_utf8_lossy(&version.stdout).trim().to_string();
    let key = digest_serialized(&(
        sdk_version,
        BUNDLED_HELPER_PROJECT,
        BUNDLED_HELPER_PROGRAM,
        BUNDLED_HELPER_QUICKFIX_PLANNER,
        BUNDLED_HELPER_RAZOR_SOURCE_FACTS,
        BUNDLED_HELPER_NUGET_CONFIG,
    ));
    let directory = cache_root.join(BUNDLED_HELPER_CACHE_NAMESPACE).join(key);
    std::fs::create_dir_all(&directory).map_err(|error| {
        diag(
            "helper_cache",
            format!("could not create helper cache: {error}"),
            Some(directory.clone()),
        )
    })?;
    Ok(directory)
}

fn bundled_helper_ready(directory: &Path) -> bool {
    directory.join(BUNDLED_HELPER_READY_MARKER).is_file() && bundled_helper_dll(directory).is_file()
}

fn lock_bundled_helper(directory: &Path) -> Result<std::fs::File, SemanticDiagnostic> {
    let path = directory.join(BUNDLED_HELPER_BUILD_LOCK);
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|error| {
            diag(
                "helper_cache",
                format!("could not open bundled helper build lock: {error}"),
                Some(path.clone()),
            )
        })?;
    lock.lock().map_err(|error| {
        diag(
            "helper_cache",
            format!("could not lock bundled helper cache: {error}"),
            Some(path),
        )
    })?;
    Ok(lock)
}

fn publish_bundled_helper(directory: &Path) -> Result<(), SemanticDiagnostic> {
    let marker = directory.join(BUNDLED_HELPER_READY_MARKER);
    let temporary = directory.join(BUNDLED_HELPER_READY_MARKER_TEMP);
    std::fs::write(&temporary, b"ready\n").map_err(|error| {
        diag(
            "helper_cache",
            format!("could not stage bundled helper readiness: {error}"),
            Some(temporary.clone()),
        )
    })?;
    std::fs::rename(&temporary, &marker).map_err(|error| {
        diag(
            "helper_cache",
            format!("could not publish bundled helper readiness: {error}"),
            Some(marker),
        )
    })
}

fn bundled_helper_dll(directory: &Path) -> PathBuf {
    directory
        .join("bin")
        .join("Release")
        .join("net10.0")
        .join("CSharpSemanticHelper.dll")
}

fn write_bundled_helper_sources(
    directory: &Path,
) -> Result<(PathBuf, PathBuf), SemanticDiagnostic> {
    let project = directory.join("CSharpSemanticHelper.csproj");
    let program = directory.join("Program.cs");
    write_if_changed(&project, BUNDLED_HELPER_PROJECT)
        .map_err(|error| diag("helper_cache", error, Some(project.clone())))?;
    write_if_changed(&program, BUNDLED_HELPER_PROGRAM)
        .map_err(|error| diag("helper_cache", error, Some(program.clone())))?;
    let planner = directory.join("QuickFixPlanner.cs");
    write_if_changed(&planner, BUNDLED_HELPER_QUICKFIX_PLANNER)
        .map_err(|error| diag("helper_cache", error, Some(planner.clone())))?;
    let razor = directory.join("RazorSourceFacts.cs");
    write_if_changed(&razor, BUNDLED_HELPER_RAZOR_SOURCE_FACTS)
        .map_err(|error| diag("helper_cache", error, Some(razor.clone())))?;
    let nuget_config = directory.join("NuGet.Config");
    write_if_changed(&nuget_config, BUNDLED_HELPER_NUGET_CONFIG)
        .map_err(|error| diag("helper_cache", error, Some(nuget_config.clone())))?;
    Ok((project, nuget_config))
}

fn build_bundled_helper(
    dotnet: &Path,
    directory: &Path,
    project: &Path,
    nuget_config: &Path,
) -> Result<PathBuf, SemanticDiagnostic> {
    let restore = Command::new(dotnet)
        .args([
            "restore",
            project.to_string_lossy().as_ref(),
            "--configfile",
            nuget_config.to_string_lossy().as_ref(),
            "--ignore-failed-sources",
            "--nologo",
        ])
        .env("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1")
        .output()
        .map_err(|error| {
            diag(
                "helper_restore",
                format!("could not restore bundled helper offline: {error}"),
                Some(project.to_path_buf()),
            )
        })?;
    if !restore.status.success() {
        return Err(diag(
            "helper_restore",
            format!(
                "bundled helper offline restore failed: {}",
                String::from_utf8_lossy(&restore.stderr)
            ),
            Some(project.to_path_buf()),
        ));
    }
    let build = Command::new(dotnet)
        .args([
            "build",
            project.to_string_lossy().as_ref(),
            "--configuration",
            "Release",
            "--no-restore",
            "--nologo",
        ])
        .env("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1")
        .output()
        .map_err(|error| {
            diag(
                "helper_build",
                format!("could not build bundled helper: {error}"),
                Some(project.to_path_buf()),
            )
        })?;
    if !build.status.success() {
        return Err(diag(
            "helper_build",
            format!(
                "bundled helper build failed: {}",
                String::from_utf8_lossy(&build.stderr)
            ),
            Some(project.to_path_buf()),
        ));
    }
    let dll = bundled_helper_dll(directory);
    if !dll.is_file() {
        return Err(diag(
            "helper_build",
            "bundled helper build produced no executable",
            Some(dll.clone()),
        ));
    }
    Ok(dll)
}
fn write_if_changed(path: &Path, contents: &str) -> Result<(), String> {
    if path.is_file() && std::fs::read_to_string(path).ok().as_deref() == Some(contents) {
        return Ok(());
    }
    std::fs::write(path, contents).map_err(|error| error.to_string())
}

fn bundled_helper_digest() -> String {
    digest_bytes(
        format!(
            "{BUNDLED_HELPER_PROJECT}\0{BUNDLED_HELPER_PROGRAM}\0{BUNDLED_HELPER_QUICKFIX_PLANNER}\0{BUNDLED_HELPER_RAZOR_SOURCE_FACTS}\0{BUNDLED_HELPER_NUGET_CONFIG}"
        )
        .as_bytes(),
    )
}

fn helper_command_digest(helper: &HelperCommand) -> String {
    let executable_digest = std::fs::read(&helper.program)
        .ok()
        .map(|bytes| digest_bytes(&bytes))
        .unwrap_or_default();
    let argument_digests: Vec<(String, String)> = helper
        .args
        .iter()
        .map(|argument| {
            let path = Path::new(argument);
            (
                argument.clone(),
                std::fs::read(path)
                    .ok()
                    .map(|bytes| digest_bytes(&bytes))
                    .unwrap_or_default(),
            )
        })
        .collect();
    digest_serialized(&(
        helper.program.to_string_lossy().to_string(),
        executable_digest,
        argument_digests,
    ))
}

fn helper_is_available(helper: &HelperCommand) -> bool {
    if helper.program.is_file() {
        return true;
    }
    if helper.program.components().count() > 1 {
        return false;
    }
    Command::new(&helper.program)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

/// Rule parameters that are meaningful only with a project semantic context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticRuleOptions {
    /// S110 `max`; Sonar's default is five parents.
    pub s110_max: u32,
    /// S110 `filteredClasses` wildcard patterns.
    #[serde(default)]
    pub s110_filtered_classes: Vec<String>,
    /// S1200 `max`; the Sonar rule is disabled by default, but the fact/rule
    /// path is available when explicitly enabled by project configuration.
    pub s1200_max: u32,
    pub s1200_enabled: bool,
}

impl Default for SemanticRuleOptions {
    fn default() -> Self {
        Self {
            s110_max: 5,
            s110_filtered_classes: Vec::new(),
            s1200_max: 30,
            s1200_enabled: false,
        }
    }
}

/// One diagnostic explaining why semantic analysis is unavailable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticDiagnostic {
    pub code: String,
    pub message: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
}

/// Availability of the complete project/compiler facts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SemanticStatus {
    Complete,
    Incomplete,
}

/// Compiler and evaluated-project identity returned by the helper.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerFingerprint {
    pub helper_version: String,
    pub compiler_version: String,
    #[serde(default)]
    pub compiler_digest: String,
    pub sdk_version: String,
    pub target_framework: String,
    pub defines: Vec<String>,
    pub language_version: String,
    pub nullable: String,
    pub project_digest: String,
    pub reference_digest: String,
    pub dependency_digest: String,
}

/// Half-open source span using 1-based lines and 0-based columns.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticSpan {
    pub start_line: u32,
    pub start_column: u32,
    pub end_line: u32,
    pub end_column: u32,
}

impl SemanticSpan {
    #[must_use]
    pub const fn valid(self) -> bool {
        self.start_line > 0
            && self.end_line > 0
            && (self.start_line < self.end_line
                || (self.start_line == self.end_line && self.start_column <= self.end_column))
    }
}

/// Roslyn supplies independent classification flags; these are serialized DTO
/// fields and cannot be replaced by a mutually exclusive enum.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent compiler DTO flags must retain their wire fields"
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticTypeRef {
    pub id: String,
    pub display_name: String,
    pub metadata_name: String,
    pub namespace: String,
    pub root_namespace: String,
    pub is_interface: bool,
    pub is_class: bool,
    pub is_struct: bool,
    pub is_sealed: bool,
}

/// Roslyn supplies independent classification flags; these are serialized DTO
/// fields and cannot be replaced by a mutually exclusive enum.
#[allow(
    clippy::struct_excessive_bools,
    reason = "independent compiler DTO flags must retain their wire fields"
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TypeFact {
    pub id: String,
    pub display_name: String,
    pub metadata_name: String,
    pub namespace: String,
    pub root_namespace: String,
    pub source_path: PathBuf,
    pub span: SemanticSpan,
    pub kind: String,
    pub is_interface: bool,
    pub is_class: bool,
    pub is_struct: bool,
    pub is_sealed: bool,
    pub is_abstract: bool,
    /// Base types in Roslyn `BaseType.SelfAndBaseTypes` order, excluding self.
    #[serde(default)]
    pub base_chain: Vec<SemanticTypeRef>,
    #[serde(default)]
    pub interfaces: Vec<SemanticTypeRef>,
    /// S1200's already symbol-bound, recursively expanded dependency set.
    #[serde(default)]
    pub dependencies: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CastFact {
    pub source_path: PathBuf,
    pub span: SemanticSpan,
    pub interface_type: SemanticTypeRef,
    pub expression_type: SemanticTypeRef,
    pub expression_is_interface: bool,
    pub impossible: bool,
    pub message: String,
}

/// A compiler-proven redundant conversion for S1905.
///
/// The helper owns the conversion/type binding decision.  Rust only projects
/// this fact after validating its source manifest and exact span.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedundantCastFact {
    pub source_path: PathBuf,
    pub span: SemanticSpan,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseTypeSuggestionFact {
    pub source_path: PathBuf,
    pub span: SemanticSpan,
    pub method_id: String,
    pub parameter_id: String,
    pub parameter_name: String,
    pub declared_type: SemanticTypeRef,
    pub suggested_type: SemanticTypeRef,
    pub safe: bool,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenericVarianceFact {
    pub source_path: PathBuf,
    pub span: SemanticSpan,
    pub owner_id: String,
    pub parameter_id: String,
    pub parameter_name: String,
    pub current_variance: String,
    pub suggested_variance: String,
    pub safe: bool,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefObjectParameterFact {
    pub source_path: PathBuf,
    pub method_span: SemanticSpan,
    pub parameter_span: SemanticSpan,
    pub method_id: String,
    pub parameter_id: String,
    pub parameter_name: String,
    pub message: String,
    pub secondary_message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlazorLambdaFact {
    /// Path of generated C# source containing the invocation.
    pub generated_path: PathBuf,
    pub generated_span: SemanticSpan,
    /// Original Razor path and mapped lambda span.  Both are required for a
    /// reportable fact; an unmapped generated finding is incomplete, not a
    /// generated-file finding.
    pub source_path: PathBuf,
    pub source_span: SemanticSpan,
    pub invocation_symbol_id: String,
    pub invocation_member: String,
    pub containing_type: String,
    pub message: String,
}
/// Exact compiler-backed source facts for a Razor document.
///
/// Razor is intentionally not represented as a C# token stream.  The SDK
/// parser classifies the exact supplied snapshot and returns only the metrics
/// needed by project measurement plus the physical lines containing code or
/// markup.  The map is validated against `source_digests` before exposure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RazorSourceFacts {
    pub metrics: hoonarqube_ir::FileMetrics,
    #[serde(default)]
    pub code_line_numbers: Vec<u32>,
}

/// All facts emitted by one helper invocation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SemanticFacts {
    pub source_digests: BTreeMap<PathBuf, String>,
    #[serde(default)]
    pub razor_source_facts: BTreeMap<PathBuf, RazorSourceFacts>,
    #[serde(default)]
    pub types: Vec<TypeFact>,
    #[serde(default)]
    pub casts: Vec<CastFact>,
    #[serde(default)]
    pub redundant_casts: Vec<RedundantCastFact>,
    #[serde(default)]
    pub base_type_suggestions: Vec<BaseTypeSuggestionFact>,
    #[serde(default)]
    pub generic_variance: Vec<GenericVarianceFact>,
    #[serde(default)]
    pub ref_object_parameters: Vec<RefObjectParameterFact>,
    #[serde(default)]
    pub blazor_lambdas: Vec<BlazorLambdaFact>,
    #[serde(default)]
    pub quick_fixes: Vec<crate::semantic_quickfix::CompilerQuickFixFact>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HelperRequest {
    schema_version: u32,
    project: PathBuf,
    target_framework: Option<String>,
    defines: Vec<String>,
    language_version: Option<String>,
    nullable: NullableMode,
    trusted_evaluation: bool,
    trusted_build: bool,
    include_razor_generated: bool,
    rules: SemanticRuleOptions,
    project_manifest_digest: String,
    sources: Vec<SourceSnapshot>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HelperResponse {
    schema_version: u32,
    status: SemanticStatus,
    #[serde(default)]
    diagnostics: Vec<SemanticDiagnostic>,
    #[serde(default)]
    compiler: CompilerFingerprint,
    #[serde(default)]
    dependency_fingerprint: String,
    #[serde(default)]
    facts: SemanticFacts,
}

/// Immutable project semantic context.  It is cheap to share between file
/// workers after one [`Self::load`] call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProjectSemanticContext {
    pub schema_version: u32,
    pub status: SemanticStatus,
    #[serde(default)]
    pub diagnostics: Vec<SemanticDiagnostic>,
    pub compiler: CompilerFingerprint,
    pub dependency_fingerprint: String,
    pub context_fingerprint: String,
    pub facts: SemanticFacts,
    pub config_digest: String,
    pub project_manifest_digest: String,
    /// Rule parameters are part of the immutable context so callers cannot
    /// reinterpret facts with a different threshold/configuration.
    pub rules: SemanticRuleOptions,
}

fn incomplete_context(
    config: &ProjectSemanticConfig,
    config_digest: &str,
    project_manifest_digest: &str,
    diagnostic: SemanticDiagnostic,
) -> ProjectSemanticContext {
    let config_digest = config_digest.to_owned();
    let project_manifest_digest = project_manifest_digest.to_owned();
    ProjectSemanticContext {
        schema_version: SEMANTIC_SCHEMA_VERSION,
        status: SemanticStatus::Incomplete,
        diagnostics: vec![diagnostic],
        compiler: CompilerFingerprint::default(),
        dependency_fingerprint: String::new(),
        context_fingerprint: digest_serialized(&(
            config_digest.clone(),
            project_manifest_digest.clone(),
        )),
        facts: SemanticFacts::default(),
        config_digest,
        project_manifest_digest,
        rules: config.rules.clone(),
    }
}

fn incomplete_context_with_diagnostics(
    config: &ProjectSemanticConfig,
    config_digest: &str,
    project_manifest_digest: &str,
    diagnostic: SemanticDiagnostic,
    diagnostics: Vec<SemanticDiagnostic>,
) -> ProjectSemanticContext {
    let mut context =
        incomplete_context(config, config_digest, project_manifest_digest, diagnostic);
    context.diagnostics.extend(diagnostics);
    context
}

fn validate_load_inputs(
    config: &ProjectSemanticConfig,
    sources: &[SourceSnapshot],
) -> Result<(), SemanticDiagnostic> {
    if !config.trusted_evaluation {
        return Err(diag(
            "evaluation_not_trusted",
            "project semantic analysis requires explicit trusted project evaluation",
            None,
        ));
    }
    if config.project.as_os_str().is_empty() {
        return Err(diag(
            "project_missing",
            "no project or solution path was configured",
            None,
        ));
    }
    if sources.is_empty() {
        return Err(diag(
            "sources_missing",
            "project semantic analysis requires the complete analyzed source snapshot set",
            None,
        ));
    }
    if let Some(bad) = sources.iter().find(|source| !source.digest_matches()) {
        return Err(diag(
            "source_digest_invalid",
            "a supplied source snapshot has an invalid content digest",
            Some(bad.path.clone()),
        ));
    }
    Ok(())
}

fn helper_for_config(config: &ProjectSemanticConfig) -> Result<HelperCommand, SemanticDiagnostic> {
    if let Some(helper) = &config.helper {
        return Ok(helper.clone());
    }
    let cache_root = std::env::var_os("HOONARQUBE_CACHE_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("XDG_CACHE_HOME").map(PathBuf::from))
        .unwrap_or_else(|| std::env::temp_dir().join("hoonarqube"));
    prepare_bundled_helper(&cache_root)
}

fn has_complete_fingerprint(response: &HelperResponse) -> bool {
    !response.dependency_fingerprint.is_empty()
        && !response.compiler.reference_digest.is_empty()
        && !response.compiler.compiler_version.is_empty()
        && !response.compiler.compiler_digest.is_empty()
}

fn finish_context(
    config: &ProjectSemanticConfig,
    config_digest: &str,
    project_manifest_digest: &str,
    response: HelperResponse,
    sources: &[SourceSnapshot],
) -> ProjectSemanticContext {
    if response.schema_version != SEMANTIC_SCHEMA_VERSION {
        return incomplete_context(
            config,
            config_digest,
            project_manifest_digest,
            diag(
                "schema_unsupported",
                format!(
                    "compiler helper schema {} is incompatible with {}",
                    response.schema_version, SEMANTIC_SCHEMA_VERSION
                ),
                None,
            ),
        );
    }
    if response.status != SemanticStatus::Complete {
        return incomplete_context_with_diagnostics(
            config,
            config_digest,
            project_manifest_digest,
            diag(
                "compiler_incomplete",
                "compiler helper could not establish a complete project/reference context",
                None,
            ),
            response.diagnostics,
        );
    }
    if !response.diagnostics.is_empty() {
        return incomplete_context_with_diagnostics(
            config,
            config_digest,
            project_manifest_digest,
            diag(
                "compiler_diagnostics",
                "compiler helper reported diagnostics; semantic findings are suppressed",
                None,
            ),
            response.diagnostics,
        );
    }
    if let Err(diagnostic) = validate_facts(&response.facts, sources) {
        return incomplete_context(config, config_digest, project_manifest_digest, diagnostic);
    }
    if response.compiler.project_digest.as_str() != project_manifest_digest {
        return incomplete_context(
            config,
            config_digest,
            project_manifest_digest,
            diag(
                "project_manifest_mismatch",
                "compiler helper did not evaluate the same complete source manifest",
                None,
            ),
        );
    }
    if !has_complete_fingerprint(&response) {
        return incomplete_context(
            config,
            config_digest,
            project_manifest_digest,
            diag(
                "compiler_fingerprint_missing",
                "compiler/reference/dependency fingerprints are required for semantic facts",
                None,
            ),
        );
    }
    let context_fingerprint = digest_serialized(&(
        SEMANTIC_SCHEMA_VERSION,
        config_digest,
        project_manifest_digest,
        &response.compiler,
        &response.dependency_fingerprint,
        &response.facts,
    ));
    ProjectSemanticContext {
        schema_version: SEMANTIC_SCHEMA_VERSION,
        status: SemanticStatus::Complete,
        diagnostics: Vec::new(),
        compiler: response.compiler,
        dependency_fingerprint: response.dependency_fingerprint,
        context_fingerprint,
        facts: response.facts,
        config_digest: config_digest.to_owned(),
        project_manifest_digest: project_manifest_digest.to_owned(),
        rules: config.rules.clone(),
    }
}
impl ProjectSemanticContext {
    /// Runs exactly one bounded helper process for the complete source set.
    /// Every failure is represented in `status`/`diagnostics`; this method does
    /// not return an empty successful graph.
    #[must_use]
    pub fn load(config: &ProjectSemanticConfig, sources: &[SourceSnapshot]) -> Self {
        let helper_source_digest = config
            .helper
            .as_ref()
            .map_or_else(bundled_helper_digest, helper_command_digest);
        let config_digest = digest_serialized(&(config, helper_source_digest));
        let project_manifest_digest = manifest_digest(sources);

        if let Err(diagnostic) = validate_load_inputs(config, sources) {
            return incomplete_context(
                config,
                &config_digest,
                &project_manifest_digest,
                diagnostic,
            );
        }
        let helper = match helper_for_config(config) {
            Ok(helper) => helper,
            Err(diagnostic) => {
                return incomplete_context(
                    config,
                    &config_digest,
                    &project_manifest_digest,
                    diagnostic,
                );
            }
        };
        if !helper_is_available(&helper) {
            return incomplete_context(
                config,
                &config_digest,
                &project_manifest_digest,
                diag(
                    "helper_unavailable",
                    "configured compiler helper executable does not exist or is not on PATH",
                    Some(helper.program.clone()),
                ),
            );
        }

        let response =
            match invoke_helper_response(config, &helper, &project_manifest_digest, sources) {
                Ok(response) => response,
                Err(diagnostic) => {
                    return incomplete_context(
                        config,
                        &config_digest,
                        &project_manifest_digest,
                        diagnostic,
                    );
                }
            };
        finish_context(
            config,
            &config_digest,
            &project_manifest_digest,
            response,
            sources,
        )
    }

    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.status == SemanticStatus::Complete && self.schema_version == SEMANTIC_SCHEMA_VERSION
    }
    /// Returns exact SDK Razor classification only for a complete context and
    /// an unchanged source snapshot.
    #[must_use]
    pub fn razor_source_facts(&self, path: &Path, source: &str) -> Option<&RazorSourceFacts> {
        if !self.is_complete() || !is_razor_path(path) {
            return None;
        }
        let canonical = canonical_or_original(path);
        let digest = self.facts.source_digests.get(&canonical).or_else(|| {
            self.facts
                .source_digests
                .iter()
                .find(|(candidate, _)| canonical_or_original(candidate) == canonical)
                .map(|(_, digest)| digest)
        })?;
        if digest != &digest_bytes(source.as_bytes()) {
            return None;
        }
        self.facts.razor_source_facts.get(&canonical).or_else(|| {
            self.facts
                .razor_source_facts
                .iter()
                .find(|(candidate, _)| canonical_or_original(candidate) == canonical)
                .map(|(_, facts)| facts)
        })
    }

    /// An additive project-aware entry point.  If the context is unavailable or
    /// the caller supplies a source different from the loaded snapshot, it
    /// returns the ordinary syntax-only report and no semantic findings.
    #[must_use]
    pub fn analyze_with_context(
        &self,
        path: PathBuf,
        source: &str,
        language: CsLanguage,
        options: &AnalyzerOptions,
    ) -> hoonarqube_ir::FileReport {
        let is_razor = is_razor_path(&path);
        let mut report = if is_razor {
            let metrics = self.razor_source_facts(&path, source).map_or(
                hoonarqube_ir::FileMetrics {
                    lines: 0,
                    code_lines: 0,
                    comment_lines: 0,
                },
                |facts| facts.metrics.clone(),
            );
            hoonarqube_ir::FileReport {
                path: path.clone(),
                language: language.prefix().to_string(),
                issues: Vec::new(),
                metrics,
            }
        } else {
            crate::analyze(path.clone(), source, language, options)
        };
        if !self.is_complete() {
            return report;
        }
        let canonical_path = canonical_or_original(&path);
        let Some(expected_digest) = self.facts.source_digests.get(&canonical_path).or_else(|| {
            self.facts
                .source_digests
                .iter()
                .find(|(candidate, _)| canonical_or_original(candidate) == canonical_path)
                .map(|(_, digest)| digest)
        }) else {
            return report;
        };
        if expected_digest != &digest_bytes(source.as_bytes()) {
            return report;
        }
        for issue in semantic_issues_for_file(self, &canonical_path, source, language) {
            if !report.issues.iter().any(|existing| {
                existing.rule_key == issue.rule_key && existing.range == issue.range
            }) {
                report.issues.push(issue);
            }
        }
        if !is_razor {
            crate::quickfix::attach_fixes(source, options, &mut report, Some(self));
        }
        hoonarqube_ir::sort_issues(&mut report.issues);
        report.path = path;
        report
    }

    /// Analyzes all snapshots against one immutable project context.  The
    /// caller is expected to construct the context once before parallel file
    /// workers and to preserve these exact source strings.
    #[must_use]
    pub fn analyze_project_with_context(
        &self,
        sources: &[SourceSnapshot],
        language: CsLanguage,
        options: &AnalyzerOptions,
    ) -> Vec<hoonarqube_ir::FileReport> {
        sources
            .iter()
            .map(|source| {
                self.analyze_with_context(source.path.clone(), &source.source, language, options)
            })
            .collect()
    }

    /// Returns whether this context has an exact fact proving a semantic span
    /// for the supplied rule.  This is useful to gate semantic quick-fixes;
    /// syntax-only fixes must not call it.
    #[must_use]
    pub fn proves_rule_span(&self, rule: &str, path: &Path, start: u32, end: u32) -> bool {
        if !self.is_complete() {
            return false;
        }
        let path = canonical_or_original(path);
        let matches = |candidate_path: &PathBuf, span: SemanticSpan| {
            canonical_or_original(candidate_path) == path
                && span.valid()
                && span.start_line == start
                && span.end_line == end
        };
        match rule {
            "csharpsquid:S110" => self.facts.types.iter().any(|fact| {
                matches(&fact.source_path, fact.span)
                    && inheritance_depth(fact, &self.rules.s110_filtered_classes)
                        > self.rules.s110_max as usize
            }),
            "csharpsquid:S1200" => self.facts.types.iter().any(|fact| {
                matches(&fact.source_path, fact.span)
                    && self.rules.s1200_enabled
                    && fact.dependencies.len() > self.rules.s1200_max as usize
            }),
            "csharpsquid:S1905" => self
                .facts
                .redundant_casts
                .iter()
                .any(|fact| matches(&fact.source_path, fact.span)),
            "csharpsquid:S1944" => self
                .facts
                .casts
                .iter()
                .any(|fact| matches(&fact.source_path, fact.span) && fact.impossible),
            "csharpsquid:S3242" => self
                .facts
                .base_type_suggestions
                .iter()
                .any(|fact| matches(&fact.source_path, fact.span) && fact.safe),
            "csharpsquid:S3246" => self
                .facts
                .generic_variance
                .iter()
                .any(|fact| matches(&fact.source_path, fact.span) && fact.safe),
            "csharpsquid:S4047" => self
                .facts
                .ref_object_parameters
                .iter()
                .any(|fact| matches(&fact.source_path, fact.method_span)),
            "csharpsquid:S6802" => self
                .facts
                .blazor_lambdas
                .iter()
                .any(|fact| matches(&fact.source_path, fact.source_span)),
            _ => false,
        }
    }
}
fn invoke_helper_response(
    config: &ProjectSemanticConfig,
    helper: &HelperCommand,
    project_manifest_digest: &str,
    sources: &[SourceSnapshot],
) -> Result<HelperResponse, SemanticDiagnostic> {
    let request = HelperRequest {
        schema_version: SEMANTIC_SCHEMA_VERSION,
        project: config.project.clone(),
        target_framework: config.target_framework.clone(),
        defines: sorted_strings(&config.defines),
        language_version: config.language_version.clone(),
        nullable: config.nullable,
        trusted_evaluation: config.trusted_evaluation,
        trusted_build: config.trusted_build,
        include_razor_generated: config.include_razor_generated,
        rules: config.rules.clone(),
        project_manifest_digest: project_manifest_digest.to_string(),
        sources: sources.to_vec(),
    };
    let request_bytes = serde_json::to_vec(&request).map_err(|error| {
        diag(
            "request_serialization",
            format!("could not serialize compiler helper request: {error}"),
            None,
        )
    })?;
    let (success, output) = invoke_helper(
        helper,
        &request_bytes,
        config.timeout_ms,
        config.max_output_bytes,
    )
    .map_err(|error| diag("helper_failed", error, Some(helper.program.clone())))?;
    let response: HelperResponse = serde_json::from_slice(&output).map_err(|error| {
        diag(
            "protocol_invalid",
            format!("compiler helper returned invalid JSON: {error}"),
            None,
        )
    })?;
    if !success && response.status != SemanticStatus::Incomplete {
        return Err(diag(
            "helper_failed",
            "compiler helper exited unsuccessfully but claimed a complete context",
            Some(helper.program.clone()),
        ));
    }
    Ok(response)
}

fn inheritance_depth(fact: &TypeFact, filtered_classes: &[String]) -> usize {
    fact.base_chain
        .iter()
        .take_while(|base| base.root_namespace == fact.root_namespace)
        .take_while(|base| !matches_filtered_class(&base.display_name, filtered_classes))
        .count()
}

fn semantic_issues_for_file(
    context: &ProjectSemanticContext,
    path: &Path,
    source: &str,
    language: CsLanguage,
) -> Vec<hoonarqube_ir::Issue> {
    let mut issues = Vec::new();
    append_type_issues(context, path, source, language, &mut issues);
    append_cast_issues(context, path, source, language, &mut issues);
    append_redundant_cast_issues(context, path, source, language, &mut issues);
    append_base_type_issues(context, path, source, language, &mut issues);
    append_generic_variance_issues(context, path, source, language, &mut issues);
    append_ref_object_issues(context, path, source, language, &mut issues);
    append_blazor_lambda_issues(context, path, source, language, &mut issues);
    issues
}

fn append_type_issues(
    context: &ProjectSemanticContext,
    path: &Path,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<hoonarqube_ir::Issue>,
) {
    for fact in &context.facts.types {
        if canonical_or_original(&fact.source_path) != path {
            continue;
        }
        let depth = inheritance_depth(fact, &context.rules.s110_filtered_classes);
        if depth > context.rules.s110_max as usize && fact.span.valid() {
            issues.push(cst::issue(
                language,
                "S110",
                format!(
                    "This {} has {} parents which is greater than {} authorized.",
                    fact.kind, depth, context.rules.s110_max
                ),
                range_from_semantic_span(fact.span, source),
            ));
        }
        if context.rules.s1200_enabled
            && fact.dependencies.len() > context.rules.s1200_max as usize
            && fact.span.valid()
        {
            issues.push(cst::issue(
                language,
                "S1200",
                format!(
                    "Split this {} into smaller and more specialized ones to reduce its dependencies on other types from {} to the maximum authorized {} or less.",
                    fact.kind,
                    fact.dependencies.len(),
                    context.rules.s1200_max
                ),
                range_from_semantic_span(fact.span, source),
            ));
        }
    }
}

fn append_cast_issues(
    context: &ProjectSemanticContext,
    path: &Path,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<hoonarqube_ir::Issue>,
) {
    for fact in &context.facts.casts {
        if canonical_or_original(&fact.source_path) == path && fact.impossible && fact.span.valid()
        {
            issues.push(cst::issue(
                language,
                "S1944",
                fact.message.clone(),
                range_from_semantic_span(fact.span, source),
            ));
        }
    }
}

fn append_redundant_cast_issues(
    context: &ProjectSemanticContext,
    path: &Path,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<hoonarqube_ir::Issue>,
) {
    for fact in &context.facts.redundant_casts {
        if canonical_or_original(&fact.source_path) == path && fact.span.valid() {
            issues.push(cst::issue(
                language,
                "S1905",
                fact.message.clone(),
                range_from_semantic_span(fact.span, source),
            ));
        }
    }
}

fn append_base_type_issues(
    context: &ProjectSemanticContext,
    path: &Path,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<hoonarqube_ir::Issue>,
) {
    for fact in &context.facts.base_type_suggestions {
        if canonical_or_original(&fact.source_path) == path && fact.safe && fact.span.valid() {
            issues.push(cst::issue(
                language,
                "S3242",
                fact.message.clone(),
                range_from_semantic_span(fact.span, source),
            ));
        }
    }
}

fn append_generic_variance_issues(
    context: &ProjectSemanticContext,
    path: &Path,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<hoonarqube_ir::Issue>,
) {
    for fact in &context.facts.generic_variance {
        if canonical_or_original(&fact.source_path) == path && fact.safe && fact.span.valid() {
            issues.push(cst::issue(
                language,
                "S3246",
                fact.message.clone(),
                range_from_semantic_span(fact.span, source),
            ));
        }
    }
}

fn append_ref_object_issues(
    context: &ProjectSemanticContext,
    path: &Path,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<hoonarqube_ir::Issue>,
) {
    let mut facts_by_method: BTreeMap<(u32, u32, u32, u32), Vec<&RefObjectParameterFact>> =
        BTreeMap::new();
    for fact in &context.facts.ref_object_parameters {
        if canonical_or_original(&fact.source_path) != path || !fact.method_span.valid() {
            continue;
        }
        let method_key = (
            fact.method_span.start_line,
            fact.method_span.start_column,
            fact.method_span.end_line,
            fact.method_span.end_column,
        );
        facts_by_method.entry(method_key).or_default().push(fact);
    }

    for (_, mut facts) in facts_by_method {
        facts.sort_by_key(|fact| {
            (
                fact.parameter_span.start_line,
                fact.parameter_span.start_column,
                fact.parameter_span.end_line,
                fact.parameter_span.end_column,
            )
        });
        let Some(first) = facts.first() else {
            continue;
        };
        let mut issue = cst::issue(
            language,
            "S4047",
            first.message.clone(),
            range_from_semantic_span(first.method_span, source),
        );
        let mut seen_parameter_spans = BTreeSet::new();
        let locations: Vec<_> = facts
            .into_iter()
            .filter_map(|fact| {
                let span = fact.parameter_span;
                if !span.valid() {
                    return None;
                }
                let span_key = (
                    span.start_line,
                    span.start_column,
                    span.end_line,
                    span.end_column,
                );
                if !seen_parameter_spans.insert(span_key) {
                    return None;
                }
                Some(hoonarqube_ir::FlowLocation::in_primary_file(
                    fact.secondary_message.clone(),
                    range_from_semantic_span(span, source),
                ))
            })
            .collect();
        if !locations.is_empty() {
            issue.flows.push(hoonarqube_ir::IssueFlow { locations });
        }
        issues.push(issue);
    }
}

fn append_blazor_lambda_issues(
    context: &ProjectSemanticContext,
    path: &Path,
    source: &str,
    language: CsLanguage,
    issues: &mut Vec<hoonarqube_ir::Issue>,
) {
    for fact in &context.facts.blazor_lambdas {
        if canonical_or_original(&fact.source_path) == path && fact.source_span.valid() {
            issues.push(cst::issue(
                language,
                "S6802",
                fact.message.clone(),
                range_from_semantic_span(fact.source_span, source),
            ));
        }
    }
}

fn validate_facts(
    facts: &SemanticFacts,
    sources: &[SourceSnapshot],
) -> Result<(), SemanticDiagnostic> {
    let expected: BTreeMap<PathBuf, String> = sources
        .iter()
        .map(|source| {
            (
                canonical_or_original(&source.path),
                source.content_digest.clone(),
            )
        })
        .collect();
    validate_source_manifest(facts, &expected)?;
    let source_text: BTreeMap<PathBuf, &str> = sources
        .iter()
        .map(|source| (canonical_or_original(&source.path), source.source.as_str()))
        .collect();
    validate_razor_facts(facts, &source_text)?;
    validate_type_facts(facts, &expected, &source_text)?;
    validate_razor_manifest(facts, sources)?;
    validate_cast_facts(facts, &expected, &source_text)?;
    validate_suggestion_facts(facts, &expected, &source_text)?;
    validate_ref_object_facts(facts, &expected, &source_text)?;
    validate_blazor_facts(facts, &expected, &source_text)?;
    validate_quick_fix_facts(facts, &source_text)?;
    Ok(())
}

fn validate_source_manifest(
    facts: &SemanticFacts,
    expected: &BTreeMap<PathBuf, String>,
) -> Result<(), SemanticDiagnostic> {
    if facts.source_digests.len() != expected.len()
        || facts
            .source_digests
            .iter()
            .any(|(path, digest)| expected.get(&canonical_or_original(path)) != Some(digest))
    {
        return Err(diag(
            "source_manifest_mismatch",
            "compiler helper facts do not cover exactly the supplied source snapshots",
            None,
        ));
    }
    Ok(())
}

fn validate_razor_facts(
    facts: &SemanticFacts,
    source_text: &BTreeMap<PathBuf, &str>,
) -> Result<(), SemanticDiagnostic> {
    for (path, fact) in &facts.razor_source_facts {
        let Some(source) = source_text.get(&canonical_or_original(path)) else {
            return Err(diag(
                "razor_fact_path_invalid",
                "compiler helper emitted Razor facts outside the source manifest",
                Some(path.clone()),
            ));
        };
        let line_count = razor_line_count(source);
        let mut code_lines = fact.code_line_numbers.clone();
        code_lines.sort_unstable();
        code_lines.dedup();
        if !is_razor_path(path)
            || fact.metrics.lines != line_count
            || u32::try_from(code_lines.len()).ok() != Some(fact.metrics.code_lines)
            || fact.metrics.code_lines > fact.metrics.lines
            || fact.metrics.comment_lines > fact.metrics.lines
            || code_lines
                .iter()
                .any(|line| *line == 0 || *line > line_count)
        {
            return Err(diag(
                "razor_fact_invalid",
                "compiler helper emitted invalid Razor source metrics or line classifications",
                Some(path.clone()),
            ));
        }
    }
    Ok(())
}

fn validate_type_facts(
    facts: &SemanticFacts,
    expected: &BTreeMap<PathBuf, String>,
    source_text: &BTreeMap<PathBuf, &str>,
) -> Result<(), SemanticDiagnostic> {
    for fact in &facts.types {
        if !valid_fact_span(expected, source_text, &fact.source_path, fact.span) {
            return Err(diag(
                "fact_span_invalid",
                "compiler helper emitted an invalid type span",
                Some(fact.source_path.clone()),
            ));
        }
    }
    Ok(())
}

fn validate_razor_manifest(
    facts: &SemanticFacts,
    sources: &[SourceSnapshot],
) -> Result<(), SemanticDiagnostic> {
    let expected_razor: BTreeSet<PathBuf> = sources
        .iter()
        .filter(|source| is_razor_path(&source.path))
        .map(|source| canonical_or_original(&source.path))
        .collect();
    let actual_razor: BTreeSet<PathBuf> = facts
        .razor_source_facts
        .keys()
        .map(|path| canonical_or_original(path))
        .collect();
    if expected_razor != actual_razor {
        return Err(diag(
            "razor_fact_missing",
            "compiler helper did not emit exact Razor facts for every supplied Razor snapshot",
            None,
        ));
    }
    Ok(())
}

fn validate_cast_facts(
    facts: &SemanticFacts,
    expected: &BTreeMap<PathBuf, String>,
    source_text: &BTreeMap<PathBuf, &str>,
) -> Result<(), SemanticDiagnostic> {
    for fact in &facts.casts {
        if !valid_fact_span(expected, source_text, &fact.source_path, fact.span) {
            return Err(diag(
                "fact_span_invalid",
                "compiler helper emitted an invalid cast span",
                Some(fact.source_path.clone()),
            ));
        }
    }
    for fact in &facts.redundant_casts {
        if !valid_fact_span(expected, source_text, &fact.source_path, fact.span) {
            return Err(diag(
                "fact_span_invalid",
                "compiler helper emitted an invalid redundant cast span",
                Some(fact.source_path.clone()),
            ));
        }
    }
    Ok(())
}

fn validate_suggestion_facts(
    facts: &SemanticFacts,
    expected: &BTreeMap<PathBuf, String>,
    source_text: &BTreeMap<PathBuf, &str>,
) -> Result<(), SemanticDiagnostic> {
    for fact in &facts.base_type_suggestions {
        if !valid_fact_span(expected, source_text, &fact.source_path, fact.span) {
            return Err(diag(
                "fact_span_invalid",
                "compiler helper emitted an invalid S3242 span",
                Some(fact.source_path.clone()),
            ));
        }
    }
    for fact in &facts.generic_variance {
        if !valid_fact_span(expected, source_text, &fact.source_path, fact.span) {
            return Err(diag(
                "fact_span_invalid",
                "compiler helper emitted an invalid S3246 span",
                Some(fact.source_path.clone()),
            ));
        }
    }
    Ok(())
}

fn validate_ref_object_facts(
    facts: &SemanticFacts,
    expected: &BTreeMap<PathBuf, String>,
    source_text: &BTreeMap<PathBuf, &str>,
) -> Result<(), SemanticDiagnostic> {
    for fact in &facts.ref_object_parameters {
        if !valid_fact_span(expected, source_text, &fact.source_path, fact.method_span)
            || !valid_fact_span(
                expected,
                source_text,
                &fact.source_path,
                fact.parameter_span,
            )
        {
            return Err(diag(
                "fact_span_invalid",
                "compiler helper emitted an invalid S4047 span",
                Some(fact.source_path.clone()),
            ));
        }
    }
    Ok(())
}

fn validate_blazor_facts(
    facts: &SemanticFacts,
    expected: &BTreeMap<PathBuf, String>,
    source_text: &BTreeMap<PathBuf, &str>,
) -> Result<(), SemanticDiagnostic> {
    for fact in &facts.blazor_lambdas {
        if !valid_fact_span(expected, source_text, &fact.source_path, fact.source_span) {
            return Err(diag(
                "fact_span_invalid",
                "compiler helper emitted an invalid Razor mapping",
                Some(fact.source_path.clone()),
            ));
        }
    }
    Ok(())
}

fn valid_fact_span(
    expected: &BTreeMap<PathBuf, String>,
    source_text: &BTreeMap<PathBuf, &str>,
    path: &Path,
    span: SemanticSpan,
) -> bool {
    expected.contains_key(&canonical_or_original(path))
        && source_text
            .get(&canonical_or_original(path))
            .is_some_and(|source| valid_semantic_span(source, span))
}

fn validate_quick_fix_facts(
    facts: &SemanticFacts,
    source_text: &BTreeMap<PathBuf, &str>,
) -> Result<(), SemanticDiagnostic> {
    for fact in &facts.quick_fixes {
        let Some(text) = source_text.get(&canonical_or_original(&fact.source_path)) else {
            return Err(diag(
                "quickfix_path_invalid",
                "compiler helper emitted a quick-fix path outside the source manifest",
                Some(fact.source_path.clone()),
            ));
        };
        if !valid_quick_fix_fact(text, fact) {
            return Err(diag(
                "quickfix_fact_invalid",
                "compiler helper emitted an invalid quick-fix fact",
                Some(fact.source_path.clone()),
            ));
        }
    }
    Ok(())
}

fn valid_quick_fix_fact(text: &str, fact: &crate::semantic_quickfix::CompilerQuickFixFact) -> bool {
    !fact.rule_key.is_empty()
        && valid_byte_span(text, fact.start_byte, fact.end_byte)
        && fact
            .actions
            .iter()
            .all(|action| valid_quick_fix_action(text, action))
}

fn valid_quick_fix_action(
    text: &str,
    action: &crate::semantic_quickfix::CompilerQuickFixAction,
) -> bool {
    !action.id.is_empty()
        && !action.edits.is_empty()
        && action
            .edits
            .iter()
            .all(|edit| valid_byte_span(text, edit.start_byte, edit.end_byte))
        && action.edits.windows(2).all(|pair| {
            pair[0].start_byte <= pair[1].start_byte && pair[0].end_byte <= pair[1].start_byte
        })
}

fn valid_byte_span(source: &str, start: usize, end: usize) -> bool {
    start <= end
        && end <= source.len()
        && source.is_char_boundary(start)
        && source.is_char_boundary(end)
}

fn valid_semantic_span(source: &str, span: SemanticSpan) -> bool {
    span.valid() && span_offsets(source, span).is_some()
}

fn invoke_helper(
    helper: &HelperCommand,
    request: &[u8],
    timeout_ms: u64,
    max_output_bytes: usize,
) -> Result<(bool, Vec<u8>), String> {
    let mut command = Command::new(&helper.program);
    command
        .args(&helper.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|error| format!("could not start compiler helper: {error}"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| "compiler helper stdout was not piped".to_string())?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| "compiler helper stderr was not piped".to_string())?;
    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| "compiler helper stdin was not piped".to_string())?;
    let overflow = Arc::new(AtomicBool::new(false));
    let stdout_overflow = Arc::clone(&overflow);
    let stderr_overflow = Arc::clone(&overflow);
    let stdout_thread =
        thread::spawn(move || read_capped(stdout, max_output_bytes, &stdout_overflow));
    let stderr_thread =
        thread::spawn(move || read_capped(stderr, max_output_bytes, &stderr_overflow));
    let request = request.to_vec();
    let stdin_thread = thread::spawn(move || {
        let mut stdin = stdin;
        let result = stdin.write_all(&request);
        drop(stdin);
        result
    });
    let timeout = Duration::from_millis(timeout_ms.max(1));
    let started = Instant::now();
    let mut timed_out = false;
    loop {
        if child
            .try_wait()
            .map_err(|error| format!("could not poll compiler helper: {error}"))?
            .is_some()
        {
            break;
        }
        if overflow.load(Ordering::Relaxed) || started.elapsed() >= timeout {
            timed_out = started.elapsed() >= timeout;
            let _ = child.kill();
            break;
        }
        thread::sleep(Duration::from_millis(5));
    }
    let status = child
        .wait()
        .map_err(|error| format!("could not reap compiler helper: {error}"))?;
    let stdin_result = stdin_thread
        .join()
        .map_err(|_| "compiler helper stdin writer panicked".to_string())?;
    let stdout = stdout_thread
        .join()
        .map_err(|_| "compiler helper stdout reader panicked".to_string())?;
    let stderr = stderr_thread
        .join()
        .map_err(|_| "compiler helper stderr reader panicked".to_string())?;
    if timed_out {
        return Err(format!(
            "compiler helper exceeded {} ms",
            timeout.as_millis()
        ));
    }
    if overflow.load(Ordering::Relaxed) {
        return Err("compiler helper output exceeded the configured bound".to_string());
    }
    if let Err(error) = stdin_result {
        return Err(format!("could not send compiler helper request: {error}"));
    }
    if !status.success() && status.code() != Some(2) {
        let error = String::from_utf8_lossy(&stderr);
        return Err(format!("compiler helper exited with {status}: {error}"));
    }
    if stdout.is_empty() {
        return Err("compiler helper returned no protocol response".to_string());
    }
    Ok((status.success(), stdout))
}

fn read_capped<R: Read>(mut reader: R, max: usize, overflow: &AtomicBool) -> Vec<u8> {
    let mut result = Vec::new();
    let mut buffer = [0_u8; 8192];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) | Err(_) => break,
            Ok(read) => {
                if result.len().saturating_add(read) <= max {
                    result.extend_from_slice(&buffer[..read]);
                } else {
                    overflow.store(true, Ordering::Relaxed);
                }
            }
        }
    }
    result
}

fn semantic_span_to_range(span: SemanticSpan) -> hoonarqube_ir::Range {
    hoonarqube_ir::Range {
        start: hoonarqube_ir::Pos {
            line: span.start_line,
            column: span.start_column,
        },
        end: hoonarqube_ir::Pos {
            line: span.end_line,
            column: span.end_column,
        },
    }
}

fn range_from_semantic_span(span: SemanticSpan, source: &str) -> hoonarqube_ir::Range {
    if !span.valid() {
        return hoonarqube_ir::Range::file_level();
    }
    let _ = source;
    semantic_span_to_range(span)
}

fn matches_filtered_class(name: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|pattern| wildcard_match(pattern, name))
}

fn wildcard_match(pattern: &str, value: &str) -> bool {
    let pattern: Vec<char> = pattern.chars().collect();
    let value: Vec<char> = value.chars().collect();
    let (mut pattern_index, mut value_index) = (0_usize, 0_usize);
    let mut star_index = None;
    let mut star_value_index = 0_usize;
    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == value[value_index] || pattern[pattern_index] == '?')
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == '*' {
            star_index = Some(pattern_index);
            pattern_index += 1;
            star_value_index = value_index;
        } else if let Some(star) = star_index {
            pattern_index = star + 1;
            star_value_index += 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }
    while pattern_index < pattern.len() && pattern[pattern_index] == '*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

fn sorted_strings(values: &[String]) -> Vec<String> {
    let mut values = values.to_vec();
    values.sort();
    values.dedup();
    values
}

fn razor_line_count(source: &str) -> u32 {
    if source.is_empty() {
        return 0;
    }
    let bytes = source.as_bytes();
    let mut terminators = 0_u32;
    let mut index = 0_usize;
    while index < bytes.len() {
        match bytes[index] {
            b'\n' => terminators = terminators.saturating_add(1),
            b'\r' if bytes.get(index + 1) != Some(&b'\n') => {
                terminators = terminators.saturating_add(1);
            }
            _ => {}
        }
        index += 1;
    }
    if source.ends_with('\n') || source.ends_with('\r') {
        terminators
    } else {
        terminators.saturating_add(1)
    }
}

fn is_razor_path(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| extension.eq_ignore_ascii_case("razor"))
}

fn canonical_or_original(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}
fn manifest_digest(sources: &[SourceSnapshot]) -> String {
    let mut entries: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = sources
        .iter()
        .map(|source| {
            (
                canonical_or_original(&source.path)
                    .to_string_lossy()
                    .as_bytes()
                    .to_vec(),
                source
                    .project
                    .as_ref()
                    .map(|project| {
                        canonical_or_original(project)
                            .to_string_lossy()
                            .into_owned()
                    })
                    .unwrap_or_default()
                    .into_bytes(),
                source.content_digest.as_bytes().to_vec(),
            )
        })
        .collect();
    entries.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
    let mut framed = b"hoonarqube-csharp-manifest-v2\0".to_vec();
    for (path, project, digest) in entries {
        framed.extend_from_slice(&(path.len() as u64).to_le_bytes());
        framed.extend_from_slice(&path);
        framed.extend_from_slice(&(project.len() as u64).to_le_bytes());
        framed.extend_from_slice(&project);
        framed.extend_from_slice(&(digest.len() as u64).to_le_bytes());
        framed.extend_from_slice(&digest);
    }
    digest_bytes(&framed)
}

fn digest_bytes(bytes: &[u8]) -> String {
    let mut digest = Sha256::new();
    digest.update(bytes);
    format!("{:x}", digest.finalize())
}
impl crate::quickfix::QuickFixSemanticFacts for ProjectSemanticContext {
    fn is_complete(&self) -> bool {
        ProjectSemanticContext::is_complete(self)
    }

    fn proves(&self, key: &str, start: usize, end: usize, source: &str) -> bool {
        if !self.is_complete() || !self.source_digest_is_loaded(source) {
            return false;
        }
        let quick_fixes: Vec<_> = self
            .facts
            .quick_fixes
            .iter()
            .filter(|fact| {
                self.facts
                    .source_digests
                    .get(&canonical_or_original(&fact.source_path))
                    .is_some_and(|digest| digest == &digest_bytes(source.as_bytes()))
            })
            .cloned()
            .collect();
        if crate::semantic_quickfix::proves(&quick_fixes, key, start, end, source) {
            return true;
        }
        let matches = |path: &PathBuf, span: SemanticSpan| {
            let Some((fact_start, fact_end)) = span_offsets(source, span) else {
                return false;
            };
            self.facts
                .source_digests
                .get(&canonical_or_original(path))
                .is_some_and(|digest| digest == &digest_bytes(source.as_bytes()))
                && fact_start == start
                && fact_end == end
        };
        match key {
            "csharpsquid:S110" => self.facts.types.iter().any(|fact| {
                matches(&fact.source_path, fact.span)
                    && inheritance_depth(fact, &self.rules.s110_filtered_classes)
                        > self.rules.s110_max as usize
            }),
            "csharpsquid:S1200" => {
                self.rules.s1200_enabled
                    && self.facts.types.iter().any(|fact| {
                        matches(&fact.source_path, fact.span)
                            && fact.dependencies.len() > self.rules.s1200_max as usize
                    })
            }
            "csharpsquid:S1905" => self
                .facts
                .redundant_casts
                .iter()
                .any(|fact| matches(&fact.source_path, fact.span)),
            "csharpsquid:S1944" => self
                .facts
                .casts
                .iter()
                .any(|fact| fact.impossible && matches(&fact.source_path, fact.span)),
            "csharpsquid:S3242" => self
                .facts
                .base_type_suggestions
                .iter()
                .any(|fact| fact.safe && matches(&fact.source_path, fact.span)),
            "csharpsquid:S3246" => self
                .facts
                .generic_variance
                .iter()
                .any(|fact| fact.safe && matches(&fact.source_path, fact.span)),
            "csharpsquid:S4047" => self
                .facts
                .ref_object_parameters
                .iter()
                .any(|fact| matches(&fact.source_path, fact.method_span)),
            "csharpsquid:S6802" => self
                .facts
                .blazor_lambdas
                .iter()
                .any(|fact| matches(&fact.source_path, fact.source_span)),
            _ => false,
        }
    }
    fn plans(
        &self,
        key: &str,
        start: usize,
        end: usize,
        source: &str,
    ) -> Vec<crate::quickfix::SemanticPlan> {
        if !self.is_complete() || !self.source_digest_is_loaded(source) {
            return Vec::new();
        }
        let digest = digest_bytes(source.as_bytes());
        let quick_fixes: Vec<_> = self
            .facts
            .quick_fixes
            .iter()
            .filter(|fact| {
                self.facts
                    .source_digests
                    .get(&canonical_or_original(&fact.source_path))
                    .is_some_and(|candidate| candidate == &digest)
            })
            .cloned()
            .collect();
        crate::semantic_quickfix::plans(&quick_fixes, key, start, end, source)
    }
}

impl ProjectSemanticContext {
    fn source_digest_is_loaded(&self, source: &str) -> bool {
        let digest = digest_bytes(source.as_bytes());
        self.facts
            .source_digests
            .values()
            .filter(|candidate| *candidate == &digest)
            .count()
            == 1
    }
}

fn span_offsets(source: &str, span: SemanticSpan) -> Option<(usize, usize)> {
    if !span.valid() {
        return None;
    }
    let offset = |line: u32, column: u32| {
        let line_start = if line == 1 {
            0
        } else {
            let mut line_start = 0;
            for _ in 1..line {
                line_start = source[line_start..].find('\n')? + line_start + 1;
            }
            line_start
        };
        let line_end = source[line_start..]
            .find('\n')
            .map_or(source.len(), |relative| line_start + relative);
        let line_text = &source[line_start..line_end];
        if column == 0 {
            return Some(line_start);
        }
        line_text
            .char_indices()
            .nth(column as usize)
            .map(|(byte, _)| line_start + byte)
            .or_else(|| (line_text.chars().count() == column as usize).then_some(line_end))
    };
    Some((
        offset(span.start_line, span.start_column)?,
        offset(span.end_line, span.end_column)?,
    ))
}

fn digest_serialized<T: Serialize>(value: &T) -> String {
    match serde_json::to_vec(value) {
        Ok(bytes) => digest_bytes(&bytes),
        Err(_) => String::new(),
    }
}

fn diag(
    code: impl Into<String>,
    message: impl Into<String>,
    path: Option<PathBuf>,
) -> SemanticDiagnostic {
    SemanticDiagnostic {
        code: code.into(),
        message: message.into(),
        path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::fs;
    use std::io::ErrorKind;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};
    #[test]
    fn source_snapshots_hash_the_exact_text() {
        let source = SourceSnapshot::new(PathBuf::from("A.cs"), "class A {}");
        assert!(source.digest_matches());
        assert_ne!(
            source.content_digest,
            SourceSnapshot::new(PathBuf::from("A.cs"), "class B {}").content_digest
        );
    }

    #[test]
    fn untrusted_context_is_structured_incomplete() {
        let context = ProjectSemanticContext::load(&ProjectSemanticConfig::default(), &[]);
        assert_eq!(context.status, SemanticStatus::Incomplete);
        assert!(!context.is_complete());
        assert!(context.dependency_fingerprint.is_empty());
    }

    fn complete_context_with_redundant_cast(
        source: &str,
        path: &Path,
        span: SemanticSpan,
    ) -> ProjectSemanticContext {
        let mut facts = SemanticFacts::default();
        let canonical = canonical_or_original(path);
        facts
            .source_digests
            .insert(canonical.clone(), digest_bytes(source.as_bytes()));
        facts.redundant_casts.push(RedundantCastFact {
            source_path: canonical,
            span,
            message: "Remove this unnecessary cast.".to_owned(),
        });
        ProjectSemanticContext {
            schema_version: SEMANTIC_SCHEMA_VERSION,
            status: SemanticStatus::Complete,
            diagnostics: Vec::new(),
            compiler: CompilerFingerprint::default(),
            dependency_fingerprint: "dependency".to_owned(),
            context_fingerprint: "context".to_owned(),
            facts,
            config_digest: "config".to_owned(),
            project_manifest_digest: "manifest".to_owned(),
            rules: SemanticRuleOptions::default(),
        }
    }

    #[test]
    fn redundant_cast_facts_project_only_for_matching_complete_sources() {
        let source =
            "class C\n{\n    void M(string o)\n    {\n        var x = (string)o;\n    }\n}\n";
        let path = PathBuf::from("RedundantCast.cs");
        let context = complete_context_with_redundant_cast(
            source,
            &path,
            SemanticSpan {
                start_line: 5,
                start_column: 17,
                end_line: 5,
                end_column: 23,
            },
        );
        let report = context.analyze_with_context(
            path.clone(),
            source,
            CsLanguage::CSharp,
            &AnalyzerOptions::default(),
        );
        let findings: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "csharpsquid:S1905")
            .collect();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].range.start.line, 5);
        assert_eq!(findings[0].range.start.column, 17);
        assert_eq!(findings[0].range.end.column, 23);
        let changed =
            "class C\n{\n    void M(string o)\n    {\n        var x = (int)o;\n    }\n}\n";
        assert!(
            context
                .analyze_with_context(
                    path,
                    changed,
                    CsLanguage::CSharp,
                    &AnalyzerOptions::default(),
                )
                .issues
                .iter()
                .all(|issue| issue.rule_key != "csharpsquid:S1905")
        );
    }

    #[test]
    fn redundant_cast_semantic_and_native_findings_are_deduplicated() {
        let source =
            "class C\n{\n    void M()\n    {\n        var value = \"x\" as string;\n    }\n}\n";
        let path = PathBuf::from("NativeAndSemanticCast.cs");
        let context = complete_context_with_redundant_cast(
            source,
            &path,
            SemanticSpan {
                start_line: 5,
                start_column: 24,
                end_line: 5,
                end_column: 33,
            },
        );
        let report = context.analyze_with_context(
            path,
            source,
            CsLanguage::CSharp,
            &AnalyzerOptions::default(),
        );
        let findings: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "csharpsquid:S1905")
            .collect();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].range.start.column, 24);
        assert_eq!(findings[0].range.end.column, 33);
    }

    #[test]
    fn redundant_cast_field_is_backward_compatible_when_wire_field_is_absent() {
        let facts: SemanticFacts = serde_json::from_str(r#"{"source_digests":{}}"#)
            .expect("older semantic facts omit redundant_casts");
        assert!(facts.redundant_casts.is_empty());
    }
    const ROADMAP_CONTRACTS_PROJECT: &str = include_str!(
        "../../../tools/oracle/fixtures/roadmap-csharp/reference-39-41/src/Contracts/Contracts.csproj"
    );
    const ROADMAP_CONTRACTS_SOURCE: &str = include_str!(
        "../../../tools/oracle/fixtures/roadmap-csharp/reference-39-41/src/Contracts/Contracts.cs"
    );
    const ROADMAP_SEMANTIC_PROJECT: &str = include_str!(
        "../../../tools/oracle/fixtures/roadmap-csharp/reference-39-41/src/SemanticFixtures/SemanticFixtures.csproj"
    );
    const ROADMAP_SEMANTIC_EDITORCONFIG: &str = include_str!(
        "../../../tools/oracle/fixtures/roadmap-csharp/reference-39-41/src/SemanticFixtures/.editorconfig"
    );
    const ROADMAP_SEMANTIC_SONARLINT: &str = include_str!(
        "../../../tools/oracle/fixtures/roadmap-csharp/reference-39-41/src/SemanticFixtures/SonarLint.xml"
    );
    const ROADMAP_SEMANTIC_SOURCE: &str = include_str!(
        "../../../tools/oracle/fixtures/roadmap-csharp/reference-39-41/src/SemanticFixtures/SemanticCases.cs"
    );
    const ROADMAP_BLAZOR_SOURCE: &str = include_str!(
        "../../../tools/oracle/fixtures/roadmap-csharp/reference-39-41/src/SemanticFixtures/BlazorInvocationCases.cs"
    );
    const S4581_PROJECT: &str = r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
</Project>
"#;
    const S4581_SOURCE: &str = r"using System;

namespace OrdinaryGuid
{
    public static class OrdinaryCase
    {
        public static Guid Create() => new Guid();
    }
}

namespace AliasedGuid
{
    using Guid = System.String;

    public static class AliasedCase
    {
        public static string PreserveAlias(string value)
        {
            Guid alias = value;
            return alias;
        }

        public static System.Guid Create() => new System.Guid();
    }
}
";

    struct OwnedTempDir(PathBuf);

    impl OwnedTempDir {
        fn new(label: &str) -> Self {
            static NEXT_ID: AtomicU64 = AtomicU64::new(0);
            const MAX_ATTEMPTS: u64 = 100;
            let pid = std::process::id();
            for _ in 0..MAX_ATTEMPTS {
                let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                let path = env::temp_dir().join(format!("hoonarqube-csharp-{label}-{pid}-{id}"));
                match fs::create_dir(&path) {
                    Ok(()) => return Self(path),
                    Err(error) if error.kind() == ErrorKind::AlreadyExists => (),
                    Err(error) => {
                        panic!(
                            "create temp directory {} for {label}: {error}",
                            path.display()
                        )
                    }
                }
            }
            panic!("create temp directory for {label}: exhausted {MAX_ATTEMPTS} attempts");
        }

        fn path(&self) -> &Path {
            &self.0
        }

        fn write(&self, relative: &str, contents: &str) -> PathBuf {
            let path = self.0.join(relative);
            fs::create_dir_all(path.parent().expect("fixture path has a parent"))
                .expect("create fixture parent");
            fs::write(&path, contents).expect("write fixture");
            path
        }
    }

    impl Drop for OwnedTempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn restore_fixture_project(dotnet: &Path, project: &Path) {
        let status = Command::new(dotnet)
            .arg("restore")
            .arg(project)
            .arg("--disable-parallel")
            .arg("--nologo")
            .env("DOTNET_SKIP_FIRST_TIME_EXPERIENCE", "1")
            .status()
            .expect("dotnet SDK is required for CSharp semantic regression coverage");
        assert!(
            status.success(),
            "restoring CSharp semantic fixture project failed: {status}"
        );
    }

    #[derive(Debug)]
    struct ExpectedSemanticFinding {
        case: &'static str,
        key: &'static str,
        line: u32,
        start_column: u32,
        end_column: u32,
        source_fragment: &'static str,
    }
    const ROADMAP_SEMANTIC_FINDINGS: &[ExpectedSemanticFinding] = &[
        ExpectedSemanticFinding {
            case: "LocalDepth6",
            key: "csharpsquid:S110",
            line: 14,
            start_column: 13,
            end_column: 24,
            source_fragment: "LocalDepth6",
        },
        ExpectedSemanticFinding {
            case: "DeepAbove",
            key: "csharpsquid:S110",
            line: 16,
            start_column: 13,
            end_column: 22,
            source_fragment: "DeepAbove",
        },
        ExpectedSemanticFinding {
            case: "DeepAt",
            key: "csharpsquid:S110",
            line: 17,
            start_column: 13,
            end_column: 19,
            source_fragment: "DeepAt",
        },
        ExpectedSemanticFinding {
            case: "CoupledAbove",
            key: "csharpsquid:S1200",
            line: 20,
            start_column: 20,
            end_column: 32,
            source_fragment: "CoupledAbove",
        },
        ExpectedSemanticFinding {
            case: "ImpossibleCastCases",
            key: "csharpsquid:S1200",
            line: 53,
            start_column: 20,
            end_column: 39,
            source_fragment: "ImpossibleCastCases",
        },
        ExpectedSemanticFinding {
            case: "BaseParameterCases",
            key: "csharpsquid:S1200",
            line: 64,
            start_column: 20,
            end_column: 38,
            source_fragment: "BaseParameterCases",
        },
        ExpectedSemanticFinding {
            case: "ImpossibleCastCases.Bad",
            key: "csharpsquid:S1944",
            line: 55,
            start_column: 54,
            end_column: 60,
            source_fragment: "(IOther)value",
        },
        ExpectedSemanticFinding {
            case: "BaseParameterCases.Bad",
            key: "csharpsquid:S3242",
            line: 66,
            start_column: 40,
            end_column: 45,
            source_fragment: "Bad(DerivedRecord",
        },
        ExpectedSemanticFinding {
            case: "BaseParameterCases.BadLocal",
            key: "csharpsquid:S3242",
            line: 72,
            start_column: 48,
            end_column: 53,
            source_fragment: "BadLocal(DerivedParameter",
        },
        ExpectedSemanticFinding {
            case: "OutputNeedsOut<T>",
            key: "csharpsquid:S3246",
            line: 87,
            start_column: 32,
            end_column: 33,
            source_fragment: "OutputNeedsOut<T>",
        },
        ExpectedSemanticFinding {
            case: "InputNeedsIn<T>",
            key: "csharpsquid:S3246",
            line: 92,
            start_column: 30,
            end_column: 31,
            source_fragment: "InputNeedsIn<T>",
        },
        ExpectedSemanticFinding {
            case: "NestedOutputNeedsOut<T>",
            key: "csharpsquid:S3246",
            line: 97,
            start_column: 38,
            end_column: 39,
            source_fragment: "NestedOutputNeedsOut<T>",
        },
        ExpectedSemanticFinding {
            case: "NestedInputInvariant<T>",
            key: "csharpsquid:S3246",
            line: 102,
            start_column: 38,
            end_column: 39,
            source_fragment: "NestedInputInvariant<T>",
        },
        ExpectedSemanticFinding {
            case: "ConstrainedOutput<T>",
            key: "csharpsquid:S3246",
            line: 112,
            start_column: 35,
            end_column: 36,
            source_fragment: "ConstrainedOutput<T>",
        },
        ExpectedSemanticFinding {
            case: "OutputDelegate<T>",
            key: "csharpsquid:S3246",
            line: 117,
            start_column: 33,
            end_column: 34,
            source_fragment: "OutputDelegate<T>",
        },
        ExpectedSemanticFinding {
            case: "InputDelegate<T>",
            key: "csharpsquid:S3246",
            line: 118,
            start_column: 35,
            end_column: 36,
            source_fragment: "InputDelegate<T>",
        },
        ExpectedSemanticFinding {
            case: "RefObject(ref object)",
            key: "csharpsquid:S4047",
            line: 122,
            start_column: 23,
            end_column: 32,
            source_fragment: "RefObject",
        },
        ExpectedSemanticFinding {
            case: "RefAlias(ref ObjectAlias)",
            key: "csharpsquid:S4047",
            line: 124,
            start_column: 23,
            end_column: 31,
            source_fragment: "RefAlias",
        },
        ExpectedSemanticFinding {
            case: "RefTwo(ref object, ref object)",
            key: "csharpsquid:S4047",
            line: 126,
            start_column: 23,
            end_column: 29,
            source_fragment: "RefTwo",
        },
    ];
    const ROADMAP_BLAZOR_FINDINGS: &[ExpectedSemanticFinding] = &[
        ExpectedSemanticFinding {
            case: "BlazorInvocationCases",
            key: "csharpsquid:S1200",
            line: 6,
            start_column: 20,
            end_column: 41,
            source_fragment: "BlazorInvocationCases",
        },
        ExpectedSemanticFinding {
            case: "BuildRenderTree",
            key: "csharpsquid:S6802",
            line: 12,
            start_column: 82,
            end_column: 101,
            source_fragment: "AddAttribute(0, \"onclick\"",
        },
    ];

    fn assert_semantic_findings(
        report: &hoonarqube_ir::FileReport,
        source: &str,
        expected: &[ExpectedSemanticFinding],
    ) {
        for key in [
            "csharpsquid:S110",
            "csharpsquid:S1200",
            "csharpsquid:S1944",
            "csharpsquid:S3242",
            "csharpsquid:S3246",
            "csharpsquid:S4047",
            "csharpsquid:S6802",
        ] {
            let expected_count = expected.iter().filter(|finding| finding.key == key).count();
            let actual_count = report
                .issues
                .iter()
                .filter(|issue| issue.rule_key == key)
                .count();
            assert_eq!(
                actual_count, expected_count,
                "unexpected {key} findings: {:?}",
                report.issues
            );
        }

        for finding in expected {
            let mut finding_matches = report.issues.iter().filter(|issue| {
                issue.rule_key == finding.key
                    && issue.range.start.line == finding.line
                    && issue.range.start.column == finding.start_column
                    && issue.range.end.line == finding.line
                    && issue.range.end.column == finding.end_column
            });
            assert!(
                finding_matches.next().is_some(),
                "{} ({}) did not produce an expected finding",
                finding.case,
                finding.key
            );
            assert!(
                finding_matches.next().is_none(),
                "{} ({}) produced more than one matching finding",
                finding.case,
                finding.key
            );
            let source_line = source
                .lines()
                .nth(finding.line.saturating_sub(1) as usize)
                .unwrap_or_else(|| panic!("{} points outside fixture source", finding.case));
            assert!(
                source_line.contains(finding.source_fragment),
                "{} does not identify its expected fixture case",
                finding.case
            );
        }
    }
    fn assert_ref_object_secondary_locations(report: &hoonarqube_ir::FileReport) {
        let expected = vec![
            (122, vec![(122, 44, 122, 49)]),
            (124, vec![(124, 48, 124, 53)]),
            (126, vec![(126, 41, 126, 46), (126, 59, 126, 65)]),
        ];
        let findings: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "csharpsquid:S4047")
            .collect();
        assert_eq!(
            findings.len(),
            expected.len(),
            "S4047 must have one primary finding per eligible method: {findings:?}"
        );
        let mut secondary_count = 0;
        for (line, locations) in expected {
            let issue = findings
                .iter()
                .find(|issue| issue.range.start.line == line)
                .unwrap_or_else(|| panic!("S4047 finding missing for line {line}"));
            assert_eq!(
                issue.message,
                "Make this method generic and replace the 'object' parameter with a type parameter."
            );
            assert_eq!(
                issue.flows.len(),
                1,
                "S4047 method on line {line} must have one secondary flow"
            );
            assert_eq!(issue.flows[0].locations.len(), locations.len());
            secondary_count += locations.len();
            for (location, (start_line, start_column, end_line, end_column)) in
                issue.flows[0].locations.iter().zip(locations)
            {
                assert_eq!(location.path, None);
                assert_eq!(
                    location.message,
                    "Replace this parameter with a type parameter."
                );
                assert_eq!(location.range.start.line, start_line);
                assert_eq!(location.range.start.column, start_column);
                assert_eq!(location.range.end.line, end_line);
                assert_eq!(location.range.end.column, end_column);
            }
        }
        assert_eq!(secondary_count, 4);
    }

    fn assert_no_semantic_finding_at(report: &hoonarqube_ir::FileReport, key: &str, lines: &[u32]) {
        for line in lines {
            assert!(
                report
                    .issues
                    .iter()
                    .all(|issue| issue.rule_key != key || issue.range.start.line != *line),
                "{key} unexpectedly flagged control line {line}"
            );
        }
    }

    #[test]
    fn compiler_backed_rules_report_roadmap_semantic_cases() {
        let workspace = OwnedTempDir::new("semantic-fixtures");
        let contracts_project_contents = ROADMAP_CONTRACTS_PROJECT.replace(
            "<Nullable>enable</Nullable>",
            "<Nullable>disable</Nullable>",
        );
        let contracts_project = workspace.write(
            "src/Contracts/Contracts.csproj",
            &contracts_project_contents,
        );
        let contracts_source =
            workspace.write("src/Contracts/Contracts.cs", ROADMAP_CONTRACTS_SOURCE);
        let semantic_project = workspace.write(
            "src/SemanticFixtures/SemanticFixtures.csproj",
            ROADMAP_SEMANTIC_PROJECT,
        );
        workspace.write(
            "src/SemanticFixtures/.editorconfig",
            ROADMAP_SEMANTIC_EDITORCONFIG,
        );
        workspace.write(
            "src/SemanticFixtures/SonarLint.xml",
            ROADMAP_SEMANTIC_SONARLINT,
        );
        let semantic_source = workspace.write(
            "src/SemanticFixtures/SemanticCases.cs",
            ROADMAP_SEMANTIC_SOURCE,
        );
        let blazor_source = workspace.write(
            "src/SemanticFixtures/BlazorInvocationCases.cs",
            ROADMAP_BLAZOR_SOURCE,
        );

        let dotnet =
            env::var_os("HOONARQUBE_DOTNET").map_or_else(|| PathBuf::from("dotnet"), PathBuf::from);
        restore_fixture_project(&dotnet, &semantic_project);
        let helper = prepare_bundled_helper(&workspace.path().join("helper-cache"))
            .expect("bundled CSharp helper must build for semantic regression coverage");

        let sources = vec![
            SourceSnapshot::new(contracts_source, ROADMAP_CONTRACTS_SOURCE)
                .with_project(contracts_project),
            SourceSnapshot::new(blazor_source.clone(), ROADMAP_BLAZOR_SOURCE)
                .with_project(semantic_project.clone()),
            SourceSnapshot::new(semantic_source.clone(), ROADMAP_SEMANTIC_SOURCE)
                .with_project(semantic_project.clone()),
        ];
        let config = ProjectSemanticConfig {
            project: semantic_project,
            helper: Some(helper),
            trusted_evaluation: true,
            timeout_ms: 120_000,
            rules: SemanticRuleOptions {
                s110_max: 5,
                s110_filtered_classes: vec!["Roadmap.Contracts.Depth3".to_owned()],
                s1200_max: 3,
                s1200_enabled: true,
            },
            ..ProjectSemanticConfig::default()
        };

        let context = ProjectSemanticContext::load(&config, &sources);
        assert!(
            context.is_complete(),
            "semantic fixture context is incomplete: {:?}",
            context.diagnostics
        );
        assert_eq!(context.compiler.nullable, "multiple:Disable,Enable");

        let options = AnalyzerOptions::default();
        let semantic_report = context.analyze_with_context(
            semantic_source,
            ROADMAP_SEMANTIC_SOURCE,
            CsLanguage::CSharp,
            &options,
        );
        assert_semantic_findings(
            &semantic_report,
            ROADMAP_SEMANTIC_SOURCE,
            ROADMAP_SEMANTIC_FINDINGS,
        );
        assert_ref_object_secondary_locations(&semantic_report);
        assert_no_semantic_finding_at(&semantic_report, "csharpsquid:S110", &[12, 13, 18]);
        assert_no_semantic_finding_at(&semantic_report, "csharpsquid:S1200", &[34, 41]);
        assert_no_semantic_finding_at(&semantic_report, "csharpsquid:S1944", &[57, 59, 61]);
        assert_no_semantic_finding_at(&semantic_report, "csharpsquid:S3242", &[68, 70, 74]);
        assert_no_semantic_finding_at(&semantic_report, "csharpsquid:S3246", &[107]);
        assert_no_semantic_finding_at(
            &semantic_report,
            "csharpsquid:S4047",
            &[131, 133, 135, 137, 139],
        );

        let blazor_report = context.analyze_with_context(
            blazor_source,
            ROADMAP_BLAZOR_SOURCE,
            CsLanguage::CSharp,
            &options,
        );
        assert_semantic_findings(
            &blazor_report,
            ROADMAP_BLAZOR_SOURCE,
            ROADMAP_BLAZOR_FINDINGS,
        );
        assert_no_semantic_finding_at(&blazor_report, "csharpsquid:S6802", &[22, 32]);
    }

    fn s3169_fixture() -> (OwnedTempDir, PathBuf, &'static str, ProjectSemanticContext) {
        const PROJECT: &str = r#"<Project Sdk="Microsoft.NET.Sdk">
  <PropertyGroup>
    <TargetFramework>net10.0</TargetFramework>
    <ImplicitUsings>enable</ImplicitUsings>
    <Nullable>enable</Nullable>
  </PropertyGroup>
</Project>
"#;
        const SOURCE: &str = r#"using System;
using System.Collections.Generic;
using System.Linq;

namespace Safe
{
    public static class SafeCase
    {
        public static int[] SafeSort(int[] items) => items.OrderBy(x => x).OrderBy(x => x).ToArray();
    }
}

namespace Unsafe
{
    public static class OrderingExtensions
    {
        public static IOrderedEnumerable<int> ThenBy(
            this IOrderedEnumerable<int> values,
            Func<int, int> key) =>
            throw new InvalidOperationException("synthetic custom extension");
    }

    public static class UnsafeCase
    {
        public static int[] UnsafeSort(int[] items) => items.OrderBy(x => x).OrderBy(x => x).ToArray();
    }
}
"#;
        let workspace = OwnedTempDir::new("quickfix-s3169");
        let project = workspace.write("src/QuickFix/QuickFix.csproj", PROJECT);
        let source_path = workspace.write("src/QuickFix/OrderingCases.cs", SOURCE);
        let dotnet =
            env::var_os("HOONARQUBE_DOTNET").map_or_else(|| PathBuf::from("dotnet"), PathBuf::from);
        restore_fixture_project(&dotnet, &project);
        let helper = prepare_bundled_helper(&workspace.path().join("helper-cache"))
            .expect("bundled CSharp helper must build for quickfix regression coverage");
        let context = ProjectSemanticContext::load(
            &ProjectSemanticConfig {
                project: project.clone(),
                helper: Some(helper),
                trusted_evaluation: true,
                timeout_ms: 120_000,
                ..ProjectSemanticConfig::default()
            },
            &[SourceSnapshot::new(source_path.clone(), SOURCE).with_project(project)],
        );
        assert!(
            context.is_complete(),
            "quickfix semantic context is incomplete: {:?}",
            context.diagnostics
        );
        (workspace, source_path, SOURCE, context)
    }

    #[test]
    fn s3169_helper_withholds_custom_thenby_but_keeps_framework_action() {
        let (_workspace, source_path, source, context) = s3169_fixture();
        let report = context.analyze_with_context(
            source_path,
            source,
            CsLanguage::CSharp,
            &AnalyzerOptions::default(),
        );
        let findings: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "csharpsquid:S3169")
            .collect();
        assert_eq!(
            findings.len(),
            2,
            "both safe and custom-ordering chains must remain diagnostics: {:?}",
            report.issues
        );
        let safe = findings
            .iter()
            .find(|issue| {
                source
                    .lines()
                    .nth(issue.range.start.line.saturating_sub(1) as usize)
                    .is_some_and(|line| line.contains("SafeSort"))
            })
            .expect("safe Enumerable chain diagnostic");
        let unsafe_chain = findings
            .iter()
            .find(|issue| {
                source
                    .lines()
                    .nth(issue.range.start.line.saturating_sub(1) as usize)
                    .is_some_and(|line| line.contains("UnsafeSort"))
            })
            .expect("custom ThenBy chain diagnostic");
        assert!(
            safe.alternatives
                .iter()
                .any(|alternative| alternative.id == "csharp.s3169.change-orderby-to-thenby"),
            "normal Enumerable S3169 must retain its action: {:?}",
            safe.alternatives
        );
        assert!(
            unsafe_chain
                .alternatives
                .iter()
                .all(|alternative| alternative.id != "csharp.s3169.change-orderby-to-thenby"),
            "custom ThenBy binding must withhold the replacement action: {:?}",
            unsafe_chain.alternatives
        );
    }
    fn s4581_fixture() -> (
        OwnedTempDir,
        ProjectSemanticConfig,
        SourceSnapshot,
        hoonarqube_ir::FileReport,
    ) {
        let workspace = OwnedTempDir::new("quickfix-s4581");
        let project = workspace.write("src/QuickFix/QuickFix.csproj", S4581_PROJECT);
        let source_path = workspace.write("src/QuickFix/GuidCases.cs", S4581_SOURCE);
        let dotnet =
            env::var_os("HOONARQUBE_DOTNET").map_or_else(|| PathBuf::from("dotnet"), PathBuf::from);
        restore_fixture_project(&dotnet, &project);
        let helper = prepare_bundled_helper(&workspace.path().join("helper-cache"))
            .expect("bundled CSharp helper must build for S4581 regression coverage");
        let config = ProjectSemanticConfig {
            project: project.clone(),
            helper: Some(helper),
            trusted_evaluation: true,
            timeout_ms: 120_000,
            ..ProjectSemanticConfig::default()
        };
        let snapshot = SourceSnapshot::new(source_path, S4581_SOURCE).with_project(project.clone());
        let context = ProjectSemanticContext::load(&config, std::slice::from_ref(&snapshot));
        assert!(
            context.is_complete(),
            "S4581 semantic context is incomplete: {:?}",
            context.diagnostics
        );
        let report = context.analyze_with_context(
            snapshot.path.clone(),
            &snapshot.source,
            CsLanguage::CSharp,
            &AnalyzerOptions::default(),
        );
        (workspace, config, snapshot, report)
    }

    #[test]
    fn s4581_helper_qualifies_guid_empty_for_shadowed_guid() {
        let (_workspace, config, snapshot, report) = s4581_fixture();
        let findings: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "csharpsquid:S4581")
            .collect();
        assert_eq!(
            findings.len(),
            2,
            "ordinary and explicitly-qualified Guid constructions must be reported: {:?}",
            report.issues
        );
        let ordinary = findings
            .iter()
            .copied()
            .find(|issue| {
                issue.alternatives.iter().any(|alternative| {
                    alternative.id == "csharp.s4581.use-guid-empty"
                        && alternative
                            .fix
                            .edits
                            .iter()
                            .any(|edit| edit.replacement == "Guid.Empty")
                })
            })
            .expect("ordinary Guid construction must receive the canonical action");
        let ordinary_action = ordinary
            .alternatives
            .iter()
            .find(|alternative| alternative.id == "csharp.s4581.use-guid-empty")
            .expect("ordinary Guid construction action");
        assert_eq!(ordinary_action.fix.edits.len(), 1);
        assert_eq!(
            ordinary_action.fix.edits[0].replacement, "Guid.Empty",
            "ordinary System.Guid must use the canonical short replacement"
        );

        let aliased = findings
            .iter()
            .copied()
            .find(|issue| {
                issue.alternatives.iter().any(|alternative| {
                    alternative.id == "csharp.s4581.use-guid-empty"
                        && alternative
                            .fix
                            .edits
                            .iter()
                            .any(|edit| edit.replacement == "global::System.Guid.Empty")
                })
            })
            .expect("explicit System.Guid construction under the Guid alias");
        let aliased_action = aliased
            .alternatives
            .iter()
            .find(|alternative| alternative.id == "csharp.s4581.use-guid-empty")
            .expect("aliased System.Guid construction action");
        assert_eq!(aliased_action.fix.edits.len(), 1);
        assert_eq!(
            aliased_action.fix.edits[0].replacement, "global::System.Guid.Empty",
            "the String alias must not be shadowed by an unqualified replacement"
        );

        let ordinary_source =
            hoonarqube_ir::apply_fixes(&snapshot.source, &[&ordinary_action.fix.edits[0]])
                .expect("ordinary S4581 edit should apply");
        assert_eq!(
            ordinary_source,
            snapshot.source.replacen("new Guid()", "Guid.Empty", 1)
        );
        let aliased_source =
            hoonarqube_ir::apply_fixes(&snapshot.source, &[&aliased_action.fix.edits[0]])
                .expect("aliased S4581 edit should apply");
        assert_eq!(
            aliased_source,
            snapshot
                .source
                .replacen("new System.Guid()", "global::System.Guid.Empty", 1)
        );
        let rewritten_source = hoonarqube_ir::apply_fixes(
            &snapshot.source,
            &[&ordinary_action.fix.edits[0], &aliased_action.fix.edits[0]],
        )
        .expect("S4581 edits should apply together");
        assert!(rewritten_source.contains("using Guid = System.String;"));
        assert!(rewritten_source.contains("Guid alias = value;"));
        assert!(rewritten_source.contains("=> Guid.Empty;"));
        assert!(rewritten_source.contains("=> global::System.Guid.Empty;"));

        let rewritten_snapshot = SourceSnapshot::new(snapshot.path.clone(), rewritten_source)
            .with_project(config.project.clone());
        let rewritten_context =
            ProjectSemanticContext::load(&config, std::slice::from_ref(&rewritten_snapshot));
        assert!(
            rewritten_context.is_complete(),
            "rewritten S4581 source must remain compiler-valid: {:?}",
            rewritten_context.diagnostics
        );
    }
}
