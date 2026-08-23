// Family 'batch5' (generated).
pub(crate) mod collectors;
pub(crate) mod collectors_hotspots;
pub(crate) mod s2187_test_framework_rules;
pub(crate) mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs this combined walker family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
