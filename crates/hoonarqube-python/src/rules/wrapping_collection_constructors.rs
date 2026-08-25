use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_wrapping_collection_constructors(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Call(call) = expr else { continue };
        let Some(name) = called_name(&call.func) else {
            continue;
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
    }
    issues
}

// --- python:S7496 — constructor wrapping an existing literal/comprehension ----

fn wrapping_redundancy(func_name: &str, argument: &Expr) -> bool {
    match func_name {
        "list" => matches!(argument, Expr::List(_) | Expr::ListComp(_)),
        "set" => matches!(argument, Expr::Set(_) | Expr::SetComp(_)),
        "dict" => matches!(argument, Expr::Dict(_) | Expr::DictComp(_)),
        _ => false,
    }
}
