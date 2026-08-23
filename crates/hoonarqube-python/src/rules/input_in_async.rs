use crate::support::dotted_name;
use crate::support::flag_sync_calls_inside_async;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_input_in_async(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    flag_sync_calls_inside_async(
        parsed.syntax().body.as_slice(),
        &|call| dotted_name(&call.func).as_deref() == Some("input"),
        "python:S7501",
        "input() blocks the event loop; use an async reader instead.",
        index,
        source,
        &mut issues,
    );
    issues
}
