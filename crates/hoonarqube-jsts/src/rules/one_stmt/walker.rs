// Family walker for 'one_stmt' (generated).
use super::s122_suite::check_suite;
use crate::JstsLanguage;
use crate::context::AnalysisContext;
use crate::support::LineIndex;
use hoonarqube_ir::Issue;
use oxc_ast::ast::Statement;

fn check_one_statement_per_line(
    body: &[Statement<'_>],
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    check_suite(body, index, language, &mut issues);
    issues
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_one_statement_per_line(ctx.program.body.as_slice(), ctx.index, ctx.language)
}
