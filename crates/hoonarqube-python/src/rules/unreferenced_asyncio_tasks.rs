use crate::engine::bindings::{KnownBinding, KnownBindings};
use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7502 / python:S7515 — asyncio task and resource lifetimes ---------

pub(crate) fn check_unreferenced_asyncio_tasks(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Some(call) = unreferenced_task(stmt, &file_ctx.known_bindings) {
            issues.push(issue_at(
                "python:S7502",
                "Keep a reference to this task; the event loop only holds a weak reference.",
                call.range(),
                index,
                source,
            ));
        }
    }
    issues
}

pub(crate) fn unreferenced_task<'s>(
    stmt: &'s Stmt,
    bindings: &KnownBindings,
) -> Option<&'s ExprCall> {
    if let Stmt::Expr(expr) = stmt
        && let Expr::Call(call) = expr.value.as_ref()
        && matches!(
            bindings.resolve_call(call),
            KnownBinding::AsyncioCreateTask | KnownBinding::AsyncioEnsureFuture
        )
    {
        Some(call)
    } else {
        None
    }
}
