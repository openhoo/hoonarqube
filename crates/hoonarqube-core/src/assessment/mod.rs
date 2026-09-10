//! Optional assessment orchestration.
//!
//! The report IR owns schema declarations. This module owns construction from
//! the caller's exact source snapshots and delegates baseline, coverage, and
//! gate algorithms to their focused modules.

pub mod baseline;
pub mod coverage;
pub mod gates;

pub use baseline::{BASELINE_SCHEMA_VERSION, BaselineMode, compare_reports, compare_to_reference};
pub use coverage::{CoverageFile, CoverageFormat, CoverageSource, import_coverage};
pub use gates::{
    GATE_CONFIG_SCHEMA_VERSION, GATE_REPORT_SCHEMA_VERSION, GateCondition, GateConfig,
    SUPPORTED_METRICS, evaluate_gate, metric_supported, supported_metrics,
};

use hoonarqube_ir::FileReport;
use hoonarqube_ir::assessment::{AnalysisContext, AssessmentError, AssessmentReport, SourceInput};

/// Builds the optional assessment artifact from the exact source bytes used by
/// analysis. No source path is opened or re-read here.
///
/// # Errors
///
/// Returns [`AssessmentError::InvalidPath`] for an unnormalizable report or
/// source path, [`AssessmentError::DuplicatePath`] for duplicate normalized
/// paths, [`AssessmentError::MissingSource`] when a report has no matching
/// source bytes, [`AssessmentError::InvalidSource`] for invalid source bytes,
/// or [`AssessmentError::Invalid`] for other invariants.
pub fn build_assessment(
    context: AnalysisContext,
    reports: &[FileReport],
    sources: &[SourceInput<'_>],
) -> Result<AssessmentReport, AssessmentError> {
    AssessmentReport::from_reports_and_source_inputs(context, reports, sources)
}
