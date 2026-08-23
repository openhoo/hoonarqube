use crate::support::CANCELLATION_SCOPE_TAILS;
use crate::support::for_each_with_in_function_context;
use crate::support::is_call_context_tail;
use crate::support::issue_at;
use crate::support::suite_contains_checkpoint;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_cancellation_scope_checkpoints(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_with_in_function_context(
        parsed.syntax().body.as_slice(),
        &mut |with_stmt, in_async| {
            if !in_async {
                return;
            }
            let is_scope = with_stmt
                .items
                .iter()
                .any(|item| is_call_context_tail(item, &CANCELLATION_SCOPE_TAILS));
            if is_scope && !suite_contains_checkpoint(&with_stmt.body) {
                issues.push(issue_at(
                    "python:S7490",
                    "Add a checkpoint (an await point) inside this cancellation scope.",
                    with_stmt.range(),
                    index,
                    source,
                ));
            }
        },
    );
    issues
}
