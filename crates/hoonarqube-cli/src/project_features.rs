//! Optional project-wide analysis features and their CLI options.
//!
//! The ordinary analyzer path intentionally does not retain source text or load
//! compiler contexts.  These options are therefore kept separate from the
//! native analyzer knobs: an empty value preserves the historical streaming
//! path, while any explicit project/assessment option opts into the bounded
//! source-snapshot path in `analyze`.

use std::path::PathBuf;

use clap::Args;
use hoonarqube_ir::FileClassification;

/// One exact source snapshot retained for an assessment or semantic run.
///
/// The source is the same UTF-8 text passed to the native analyzer.  Keeping it
/// here prevents a second filesystem read and lets compiler-backed contexts and
/// assessment identity operate on exactly the bytes that produced the report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AnalyzedSource {
    pub(crate) path: PathBuf,
    pub(crate) source: String,
    pub(crate) classification: FileClassification,
}

/// Shared compiler/project options used by `analyze` and `fix`.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct SemanticOptions {
    /// TypeScript project configuration (`tsconfig.json`) to load.
    #[arg(long = "typescript-project")]
    pub(crate) typescript_project: Option<PathBuf>,
    /// Explicit TypeScript package/compiler location.
    #[arg(long = "typescript-module")]
    pub(crate) typescript_module: Option<PathBuf>,
    /// S4328 package name or scope allowed by project policy. Repeat for more.
    #[arg(
        long = "typescript-dependency-whitelist",
        requires = "typescript_project"
    )]
    pub(crate) typescript_dependency_whitelist: Vec<String>,
    /// C# project or solution to load for compiler-backed rules.
    #[arg(long = "csharp-project")]
    pub(crate) csharp_project: Option<PathBuf>,
    /// Additional explicit C# source snapshots supplied only to the compiler context.
    /// Repeat for project files that are not positional analysis inputs.
    #[arg(long = "csharp-context-source", requires = "csharp_project")]
    pub(crate) csharp_context_sources: Vec<PathBuf>,
    /// Maximum parent-type depth for C# S110. The default remains five.
    #[arg(long = "csharp-s110-max", requires = "csharp_project")]
    pub(crate) csharp_s110_max: Option<u32>,
    /// C# S110 filtered-class wildcard pattern. Repeat for multiple patterns.
    #[arg(long = "csharp-s110-filtered-class", requires = "csharp_project")]
    pub(crate) csharp_s110_filtered_class: Vec<String>,
    /// Maximum dependency count for C# S1200. Supplying this enables S1200.
    #[arg(long = "csharp-s1200-max", requires = "csharp_project")]
    pub(crate) csharp_s1200_max: Option<u32>,
    /// Maximum wall-clock time for the C# semantic helper, in milliseconds.
    /// The default remains 30,000 ms; this bounded override requires a
    /// C# project and must be positive and finite.
    #[arg(
        long = "csharp-timeout-ms",
        requires = "csharp_project",
        value_parser = parse_positive_u64
    )]
    pub(crate) csharp_timeout_ms: Option<u64>,
    /// Permit evaluation/building an `MSBuild` or Razor project supplied above.
    /// When trusted Razor snapshots are present, generated-source analysis is
    /// requested automatically. Without this explicit trust opt-in, the
    /// project is not executed.
    #[arg(long = "allow-project-build")]
    pub(crate) allow_project_build: bool,
    /// Python project root/module configuration for cross-file rules.
    #[arg(long = "python-project")]
    pub(crate) python_project: Option<PathBuf>,
}

fn parse_positive_u64(value: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|_| "must be a positive finite integer".to_owned())?;
    if parsed == 0 {
        return Err("must be a positive finite integer".to_owned());
    }
    Ok(parsed)
}

impl SemanticOptions {
    /// Whether a compiler/project context was explicitly requested.
    #[must_use]
    pub(crate) const fn requested(&self) -> bool {
        self.typescript_project.is_some()
            || self.typescript_module.is_some()
            || !self.typescript_dependency_whitelist.is_empty()
            || self.csharp_project.is_some()
            || !self.csharp_context_sources.is_empty()
            || self.csharp_s110_max.is_some()
            || !self.csharp_s110_filtered_class.is_empty()
            || self.csharp_s1200_max.is_some()
            || self.csharp_timeout_ms.is_some()
            || self.python_project.is_some()
    }
}

/// Optional coverage, baseline, gate, and compiler-backed project features.
#[derive(Args, Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProjectFeatureOptions {
    /// Shared compiler/project options.
    #[command(flatten)]
    pub(crate) semantics: SemanticOptions,
    /// LCOV coverage artifacts.  Repeat the option for multiple inputs.
    #[arg(long = "coverage-lcov")]
    pub(crate) coverage_lcov: Vec<PathBuf>,
    /// `OpenCover` XML coverage artifacts.  Repeat the option for multiple inputs.
    #[arg(long = "coverage-opencover")]
    pub(crate) coverage_opencover: Vec<PathBuf>,
    /// Pinned native assessment report used as the baseline reference.
    #[arg(long = "baseline")]
    pub(crate) baseline: Option<PathBuf>,
    /// Atomically write the complete current native assessment report here.
    #[arg(long = "write-baseline")]
    pub(crate) write_baseline: Option<PathBuf>,
    /// Versioned quality-gate configuration.
    #[arg(long = "quality-gate")]
    pub(crate) quality_gate: Option<PathBuf>,
    /// Capture versioned assessment provenance even without another assessment input.
    #[arg(long = "assessment")]
    pub(crate) assessment: bool,
}

impl ProjectFeatureOptions {
    /// Returns true when analysis must retain source snapshots and build the
    /// optional assessment artifact.
    #[must_use]
    pub(crate) const fn assessment_requested(&self) -> bool {
        self.assessment
            || !self.coverage_lcov.is_empty()
            || !self.coverage_opencover.is_empty()
            || self.baseline.is_some()
            || self.write_baseline.is_some()
            || self.quality_gate.is_some()
    }

    /// Returns true when one or more explicit compiler/project contexts must be
    /// loaded before per-file workers run.
    #[must_use]
    pub(crate) const fn semantics_requested(&self) -> bool {
        self.semantics.requested()
    }
}
