// Family 'one_stmt' (generated).
mod s122_suite;
mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs every rule of this family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
