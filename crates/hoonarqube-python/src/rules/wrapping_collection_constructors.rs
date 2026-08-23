use crate::support::called_name;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use crate::support::wrapping_redundancy;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_wrapping_collection_constructors(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Call(call) = expr else { return };
        let Some(name) = called_name(&call.func) else {
            return;
        };
        if call.arguments.keywords.is_empty()
            && let [only] = &call.arguments.args[..]
            && wrapping_redundancy(name, only)
        {
            issues.push(issue_at(
                "python:S7496",
                "Use the inner literal or comprehension directly; this wrapping is redundant.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
