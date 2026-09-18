use crate::support::call_parts;
use crate::support::called_name;
use crate::support::for_each_expr;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_single_task_nurseries(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_nursery_block(parsed.syntax().body.as_slice(), &mut |with_stmt| {
        if nursery_started_tasks(with_stmt) == 1 {
            issues.push(issue_at(
                "python:S7513",
                "Start this task directly instead of opening a nursery for one task.",
                with_stmt.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- python:S7513 / python:S7514 — nursery blocks ------------------------------------

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

const NURSERY_START_CALLS: [&str; 4] = ["start_soon", "start_soon_nursery", "spawn", "create_task"];

fn nursery_started_tasks(with_stmt: &ruff_python_ast::StmtWith) -> usize {
    // Sonar counts tasks actually spawned: a start call inside a loop
    // spawns one task per iteration, so it never reads as "one task".
    count_spawn_calls(with_stmt.body.as_slice(), false)
}

fn count_spawn_calls(stmts: &[Stmt], in_loop: bool) -> usize {
    let mut count = 0;
    for stmt in stmts {
        match stmt {
            Stmt::For(inner) => {
                count += count_spawn_calls(&inner.body, true);
                count += count_spawn_calls(&inner.orelse, in_loop);
            }
            Stmt::While(inner) => {
                count += count_spawn_calls(&inner.body, true);
                count += count_spawn_calls(&inner.orelse, in_loop);
            }
            // Nested functions/classes spawn their tasks at call time, not
            // when the nursery block runs.
            Stmt::FunctionDef(_) | Stmt::ClassDef(_) => {}
            _ => {
                for expr in stmt_exprs(stmt) {
                    for_each_expr(expr, &mut |expr| {
                        if let Expr::Call(call) = expr
                            && !in_loop
                            && called_name(&call.func)
                                .is_some_and(|name| NURSERY_START_CALLS.contains(&name))
                        {
                            count += 1;
                        }
                    });
                }
                for body in crate::support::child_bodies(stmt) {
                    count += count_spawn_calls(body, in_loop);
                }
            }
        }
    }
    count
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

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s7513_flags_nurseries_starting_single_tasks() {
        let flagged = scan(concat!(
            "async def one():\n",
            "    async with trio.open_nursery() as nursery:\n",
            "        nursery.start_soon(work)\n",
            "async def many():\n",
            "    async with trio.open_nursery() as nursery:\n",
            "        nursery.start_soon(a)\n",
            "        nursery.start_soon(b)\n"
        ));
        assert_eq!(findings(&flagged, "python:S7513").len(), 1);
    }

    #[test]
    fn s7513_counts_spawned_tasks_not_create_task_call_sites() {
        // Issue #650: a single `create_task` call site inside a loop spawns
        // one task per iteration, so the group is not a single-task nursery.
        let loop_spawned = scan(concat!(
            "import asyncio\n",
            "async def run_all(coros):\n",
            "    async with asyncio.TaskGroup() as tg:\n",
            "        for coro in coros:\n",
            "            tg.create_task(coro)\n",
            "async def retry(jobs):\n",
            "    async with asyncio.TaskGroup() as tg:\n",
            "        while jobs:\n",
            "            tg.create_task(jobs.pop())\n"
        ));
        assert_eq!(findings(&loop_spawned, "python:S7513").len(), 0);

        // A group that only ever spawns one task is still flagged.
        let single = scan(concat!(
            "import asyncio\n",
            "async def one(job):\n",
            "    async with asyncio.TaskGroup() as tg:\n",
            "        tg.create_task(job)\n"
        ));
        assert_eq!(findings(&single, "python:S7513").len(), 1);
    }
}
