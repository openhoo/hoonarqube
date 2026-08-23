use crate::support::called_name;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7498 — literal syntax for empty collections ----------------------

pub(crate) fn check_empty_collection_constructors(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Call(call) = expr else { return };
        if !call.arguments.args.is_empty() {
            return;
        }
        let literal_shaped = matches!(
            called_name(&call.func),
            Some("list" | "set" | "tuple" | "dict")
        ) && (call.arguments.keywords.is_empty()
            || called_name(&call.func) == Some("dict")
                && call
                    .arguments
                    .keywords
                    .iter()
                    .all(|keyword| keyword.arg.is_some()));
        if literal_shaped {
            issues.push(issue_at(
                "python:S7498",
                "Replace this call with the equivalent collection literal.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}
