use crate::support::SYNC_HTTP_CALLS;
use crate::support::dotted_name;
use crate::support::flag_sync_calls_inside_async;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_sync_http_in_async(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    flag_sync_calls_inside_async(
        parsed.syntax().body.as_slice(),
        &|call| {
            dotted_name(&call.func).is_some_and(|path| SYNC_HTTP_CALLS.contains(&path.as_str()))
        },
        "python:S7499",
        "Use an async HTTP client inside async functions.",
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
    fn s7499_flags_sync_http_clients_in_async_functions() {
        let flagged =
            scan("async def web():\n    requests.get(\"http://x\")\n    await asyncio.sleep(1)\n");
        assert_eq!(findings(&flagged, "python:S7499").len(), 1);
    }
}
