use crate::support::for_each_call;
use crate::support::int_literal_value;
use crate::support::issue_at;
use crate::support::sleep_call_tail;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7486 — long sleeps --------------------------------------------------

pub(crate) fn check_long_sleeps(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    const LONG_SLEEP_SECONDS: i64 = 60;
    let mut issues = Vec::new();
    for_each_call(parsed.syntax().body.as_slice(), &mut |call| {
        if sleep_call_tail(call).is_some()
            && let [only] = &call.arguments.args[..]
            && int_literal_value(only).is_some_and(|seconds| seconds >= LONG_SLEEP_SECONDS)
        {
            issues.push(issue_at(
                "python:S7486",
                "Use sleep_forever or an event instead of this long sleep.",
                call.range(),
                index,
                source,
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s7486_flags_only_long_sleeps() {
        let flagged = scan("await asyncio.sleep(59)\nawait asyncio.sleep(60)\n");
        let found = findings(&flagged, "python:S7486");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 2);
    }
}
