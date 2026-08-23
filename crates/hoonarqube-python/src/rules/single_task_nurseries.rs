use crate::support::for_each_nursery_block;
use crate::support::issue_at;
use crate::support::nursery_started_tasks;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
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
