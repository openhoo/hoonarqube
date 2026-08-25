// --- python:S7513 / python:S7514 — nursery blocks

use crate::support::{call_parts, for_each_stmt};
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;

pub(crate) fn nursery_context_expression(expr: &Expr) -> bool {
    match expr {
        Expr::Name(name) => {
            matches!(name.id.as_str(), "nursery" | "task_group")
        }
        _ => call_parts(expr).is_some_and(|(path, _)| {
            matches!(
                path.as_str(),
                "trio.open_nursery"
                    | "anyio.create_task_group"
                    | "asyncio.TaskGroup"
                    | "open_nursery"
                    | "create_task_group"
                    | "TaskGroup"
            )
        }),
    }
}

pub(crate) fn is_nursery_block(with_stmt: &ruff_python_ast::StmtWith) -> bool {
    with_stmt.is_async
        && with_stmt
            .items
            .iter()
            .any(|item| nursery_context_expression(&item.context_expr))
}

pub(crate) fn for_each_nursery_block(
    module_body: &[Stmt],
    visit: &mut impl FnMut(&ruff_python_ast::StmtWith),
) {
    for_each_stmt(module_body, &mut |stmt| {
        if let Stmt::With(with_stmt) = stmt
            && is_nursery_block(with_stmt)
        {
            visit(with_stmt);
        }
    });
}
