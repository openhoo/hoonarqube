use crate::support::dotted_name;
use crate::support::flag_sync_calls_inside_async;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_sync_subprocess_in_async(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    flag_sync_calls_inside_async(
        parsed.syntax().body.as_slice(),
        &|call| {
            dotted_name(&call.func)
                .is_some_and(|path| SYNC_SUBPROCESS_CALLS.contains(&path.as_str()))
        },
        "python:S7487",
        "Run this subprocess through asyncio.subprocess inside async functions.",
        index,
        source,
        &mut issues,
    );
    issues
}

// --- migrated from support/mod.rs (S7487) ---
// --- python:S7487 / S7493 / S7499 / S7501 / S7488 / S7489 — blocking calls -------

const SYNC_SUBPROCESS_CALLS: [&str; 5] = [
    "subprocess.run",
    "subprocess.call",
    "subprocess.check_call",
    "subprocess.check_output",
    "subprocess.Popen",
];

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s7487_flags_sync_subprocess_in_async_functions() {
        let flagged = scan(concat!(
            "async def run_cmd():\n",
            "    subprocess.run([\"ls\"])\n",
            "    await asyncio.sleep(1)\n"
        ));
        assert_eq!(findings(&flagged, "python:S7487").len(), 1);
    }
}
