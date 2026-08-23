use crate::support::SYNC_OS_CALLS;
use crate::support::dotted_name;
use crate::support::flag_sync_calls_inside_async;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_sync_os_calls_in_async(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    flag_sync_calls_inside_async(
        parsed.syntax().body.as_slice(),
        &|call| dotted_name(&call.func).is_some_and(|path| SYNC_OS_CALLS.contains(&path.as_str())),
        "python:S7489",
        "Run this OS command asynchronously inside async functions.",
        index,
        source,
        &mut issues,
    );
    issues
}
