// Family 'one_stmt' (generated).
pub(crate) mod walker;
pub(crate) mod s122_suite;

use crate::context::AnalysisContext;
use crate::Issue;

/// Runs every rule of this family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    let mut issues = Vec::new();
    issues.extend(s122_suite::check(ctx));
    issues
}


