use crate::support::called_name;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use crate::support::single_positional_call;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_generator_into_constructor(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        if matches!(expr, Expr::Call(call) if matches!(called_name(&call.func), Some("list" | "set")))
            && let Some(argument) =
                single_positional_call(expr, "list").or_else(|| single_positional_call(expr, "set"))
            && matches!(argument, Expr::Generator(_))
        {
            issues.push(issue_at(
                "python:S7494",
                "Use a comprehension instead of passing a generator expression here.",
                expr.range(),
                index,
                source,
            ));
        }
    });
    issues
}
