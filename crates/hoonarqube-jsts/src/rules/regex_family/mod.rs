// Family 'regex_family' (generated).
pub(crate) mod collectors;
mod s5856_constant_regex_site;
mod s6328_replacement_groups;
mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs every rule of this family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
