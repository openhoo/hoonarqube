use crate::support::called_name;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7505 — map with lambda ----------------------------------------------

pub(crate) fn check_map_lambda_calls(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Call(call) = expr else { return };
        if called_name(&call.func) == Some("map")
            && call
                .arguments
                .args
                .first()
                .is_some_and(|first| matches!(first, Expr::Lambda(_)))
        {
            issues.push(issue_at(
                "python:S7505",
                "Replace this 'map' call with a comprehension.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
