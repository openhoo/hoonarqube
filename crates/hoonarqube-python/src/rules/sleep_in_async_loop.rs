use crate::context::FnContext;
use crate::context::context_is_async;
use crate::context::for_each_stmt_in_fn_context;
use crate::support::issue_at;
use crate::support::sleep_call_tail;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7484 — sleep awaited inside an async loop --------------------------

pub(crate) fn check_sleep_in_async_loop(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_in_fn_context(
        parsed.syntax().body.as_slice(),
        FnContext {
            nearest_function: None,
            loop_depth: 0,
        },
        &mut |stmt, ctx| {
            if ctx.loop_depth == 0 || !context_is_async(ctx) {
                return;
            }
            if let Stmt::Expr(expr) = stmt
                && let Expr::Await(awaited) = expr.value.as_ref()
                && let Expr::Call(call) = awaited.value.as_ref()
                && sleep_call_tail(call).is_some()
            {
                issues.push(issue_at(
                    "python:S7484",
                    "Await an event or use a cancellation-aware sleep inside this loop.",
                    awaited.range(),
                    index,
                    source,
                ));
            }
        },
    );
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s7484_flags_sleep_awaits_inside_async_loops() {
        let flagged = scan(concat!(
            "async def poll(client):\n",
            "    while True:\n",
            "        await asyncio.sleep(1)\n",
            "async def once(client):\n",
            "    await asyncio.sleep(1)\n"
        ));
        let found = findings(&flagged, "python:S7484");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }
}
