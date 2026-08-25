use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7498 — literal syntax for empty collections ----------------------

pub(crate) fn check_empty_collection_constructors(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Call(call) = expr else { continue };
        if !call.arguments.args.is_empty() {
            continue;
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
    }
    issues
}
