// Family 'one_stmt' (generated).
pub(crate) mod collectors;
pub(crate) mod s122_suite;
pub(crate) mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs every rule of this family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
