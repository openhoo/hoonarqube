// Family 'batch2d' (generated).
pub(crate) mod collectors;
pub(crate) mod s3512_es_idioms;
pub(crate) mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs every rule of this family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
