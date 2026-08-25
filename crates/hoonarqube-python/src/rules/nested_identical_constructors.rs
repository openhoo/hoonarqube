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

pub(crate) fn check_nested_identical_constructors(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Some(outer_name) = constructor_name(expr) else {
            return;
        };
        let Some(outer_argument) = single_positional_call(expr, outer_name) else {
            return;
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
    });
    issues
}

// --- migrated from support/mod.rs (S7508) ---
// --- python:S7508 — redundant identical nested constructors ----------------------

/// Name of a collection-constructor call (`list`, `set`, `tuple`, `frozenset`).
fn constructor_name(expr: &Expr) -> Option<&str> {
    let Expr::Call(call) = expr else { return None };
    let name = called_name(&call.func)?;
    matches!(name, "list" | "set" | "tuple" | "frozenset").then_some(name)
}
