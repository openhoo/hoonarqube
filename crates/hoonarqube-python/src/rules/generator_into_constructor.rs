use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_generator_into_constructor(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
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
    }
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
