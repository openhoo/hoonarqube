use crate::support::ASYNC_FILE_METHODS;
use crate::support::SYNC_FILE_CALLS;
use crate::support::called_name;
use crate::support::dotted_name_in;
use crate::support::flag_sync_calls_inside_async;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_sync_file_ops_in_async(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    flag_sync_calls_inside_async(
        parsed.syntax().body.as_slice(),
        &|call| {
            dotted_name_in(&call.func, &SYNC_FILE_CALLS)
                || called_name(&call.func).is_some_and(|name| ASYNC_FILE_METHODS.contains(&name))
        },
        "python:S7493",
        "Use async file APIs instead of this blocking file operation.",
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
    fn s7493_flags_blocking_file_operations_in_async_functions() {
        let flagged = scan(concat!(
            "async def rd():\n",
            "    data = open(\"f\").read()\n",
            "    text = p.read_text()\n",
            "    await asyncio.sleep(1)\n"
        ));
        assert_eq!(findings(&flagged, "python:S7493").len(), 2);
    }
}
