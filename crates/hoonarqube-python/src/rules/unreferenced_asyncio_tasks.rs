use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
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
        if let Stmt::Expr(expr_stmt) = stmt
            && let Expr::Call(call) = expr_stmt.value.as_ref()
            && called_name(&call.func)
                .is_some_and(|tail| matches!(tail, "create_task" | "ensure_future"))
        {
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
