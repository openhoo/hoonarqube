// Family walker for 'one_stmt' (generated).
use crate::context::AnalysisContext;
use hoonarqube_ir::Issue;

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    super::s122_suite::check_suite(ctx)
}
