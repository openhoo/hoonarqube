// Family 'naming' (generated).
pub(crate) mod walker;

use crate::context::AnalysisContext;
use crate::Issue;

/// Runs this combined walker family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}


