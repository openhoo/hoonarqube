use crate::support::for_each_stmt;
use crate::support::stmt_exprs;
use crate::support::visit_ifexp_branches;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_nested_conditional_expressions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        for expr in stmt_exprs(stmt) {
            visit_ifexp_branches(expr, false, &mut issues, index, source);
        }
    });
    issues
}
