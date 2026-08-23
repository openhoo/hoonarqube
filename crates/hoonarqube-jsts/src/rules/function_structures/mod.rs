// Family 'function_structures' (generated).
pub(crate) mod s2376_class_getter_pairing;
pub(crate) mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs every rule of this family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
