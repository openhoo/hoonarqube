// Family 'statement_sequences' (generated).
pub(crate) mod s1488_scan_statement_sequence;
mod walker;

use crate::Issue;
use crate::context::AnalysisContext;

/// Runs every rule of this family.
pub(crate) fn run_all(ctx: &AnalysisContext) -> Vec<Issue> {
    walker::run(ctx)
}
