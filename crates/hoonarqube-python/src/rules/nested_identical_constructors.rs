use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::issue_at;
use crate::support::single_positional_call;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_nested_identical_constructors(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Some(outer_name) = constructor_name(expr) else {
            continue;
        };
        let Some(outer_argument) = single_positional_call(expr, outer_name) else {
            continue;
        };
        if constructor_name(outer_argument) == Some(outer_name) {
            issues.push(issue_at(
                "python:S7508",
                "Remove the redundant nested call; the outer constructor adds nothing.",
                expr.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S7508 — redundant identical nested constructors ----------------------

/// Name of a collection-constructor call (`list`, `set`, `tuple`, `frozenset`).
fn constructor_name(expr: &Expr) -> Option<&str> {
    let Expr::Call(call) = expr else { return None };
    let name = called_name(&call.func)?;
    matches!(name, "list" | "set" | "tuple" | "frozenset").then_some(name)
}
