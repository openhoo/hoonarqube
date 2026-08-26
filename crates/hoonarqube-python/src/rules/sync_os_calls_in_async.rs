use crate::support::SYNC_OS_CALLS;
use crate::support::dotted_name_in;
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
        &|call| dotted_name_in(&call.func, &SYNC_OS_CALLS),
        "python:S7489",
        "Run this OS command asynchronously inside async functions.",
        index,
        source,
        &mut issues,
    );
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s7489_flags_sync_os_calls_in_async_functions() {
        let flagged = scan("async def sh():\n    os.system(\"ls\")\n    await asyncio.sleep(1)\n");
        assert_eq!(findings(&flagged, "python:S7489").len(), 1);
    }
}
