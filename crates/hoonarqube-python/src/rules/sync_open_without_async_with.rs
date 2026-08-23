use crate::support::for_each_with_in_function_context;
use crate::support::is_call_to;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_sync_open_without_async_with(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_with_in_function_context(
        parsed.syntax().body.as_slice(),
        &mut |with_stmt, in_async| {
            if !in_async || with_stmt.is_async {
                return;
            }
            for item in &with_stmt.items {
                if is_call_to(&item.context_expr, "open") {
                    issues.push(issue_at(
                        "python:S7515",
                        "Open this resource with 'async with' so it does not block the event loop.",
                        item.context_expr.range(),
                        index,
                        source,
                    ));
                }
            }
        },
    );
    issues
}
