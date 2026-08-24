use crate::support::called_name;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
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

// --- migrated from support/mod.rs (S7494) ---
// --- python:S7494 — comprehension over a generator expression -----------------

/// `(name, sole positional argument)` for calls shaped `name(x)` without
/// keywords.
pub(crate) fn single_positional_call<'a>(expr: &'a Expr, name: &str) -> Option<&'a Expr> {
    match expr {
        Expr::Call(call)
            if called_name(&call.func) == Some(name)
                && call.arguments.args.len() == 1
                && call.arguments.keywords.is_empty() =>
        {
            Some(&call.arguments.args[0])
        }
        _ => None,
    }
}
