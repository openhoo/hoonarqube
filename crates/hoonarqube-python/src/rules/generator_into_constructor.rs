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
        let Expr::Call(call) = expr else { continue };
        let Expr::Name(callee) = call.func.as_ref() else {
            continue;
        };
        let name = callee.id.as_str();
        if !matches!(name, "list" | "set") {
            continue;
        }
        if single_positional_call(expr, name)
            .is_some_and(|argument| matches!(argument, Expr::Generator(_)))
        {
            issues.push(issue_at(
                "python:S7494",
                &format!("Replace {name} constructor call with a {name} comprehension."),
                call.func.range(),
                index,
                source,
            ));
        }
    }
    issues
}

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
