// Family 'duplicate' (generated).
pub(crate) mod collectors;
pub(crate) mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs this combined walker family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
