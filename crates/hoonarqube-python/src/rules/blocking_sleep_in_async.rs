use crate::engine::bindings::KnownBinding;
use crate::engine::file_context::FileContext;
use crate::support::flag_sync_calls_inside_async;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_blocking_sleep_in_async(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    flag_sync_calls_inside_async(
        parsed.syntax().body.as_slice(),
        &|call| {
            matches!(
                file_ctx.known_bindings.resolve_call(call),
                KnownBinding::TimeSleep
            )
        },
        "python:S7488",
        "Await asyncio.sleep instead of blocking the event loop with time.sleep.",
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
    fn s7488_flags_bound_blocking_time_sleep_in_async_functions() {
        let flagged =
            scan("import time\nasync def tick():\n    time.sleep(1)\n    await asyncio.sleep(1)\n");
        assert_eq!(findings(&flagged, "python:S7488").len(), 1);
    }

    #[test]
    fn s7488_ignores_shadowed_time_bindings() {
        let shadowed = scan("import time\nasync def tick(time):\n    time.sleep(1)\n");
        assert!(findings(&shadowed, "python:S7488").is_empty());
    }
}
