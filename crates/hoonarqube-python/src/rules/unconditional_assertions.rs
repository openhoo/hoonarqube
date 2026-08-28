use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::unconditional_assert_verdict;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_unconditional_assertions(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if unconditional_assert_verdict(call, source).is_some() {
            issues.push(issue_at(
                "python:S5914",
                "Replace this expression; its boolean value is constant.",
                call.arguments.args[0].range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5914_flags_only_constant_boolean_assertions() {
        let flagged =
            scan("case.assertTrue(True)\ncase.assertFalse(False)\ncase.assertEqual(a, a)\n");
        let issues = findings(&flagged, "python:S5914");
        assert_eq!(issues.len(), 2);
        assert!(issues.iter().all(
            |issue| issue.message == "Replace this expression; its boolean value is constant."
        ));
        assert_eq!(
            (issues[0].range.start.line, issues[0].range.start.column),
            (1, 16)
        );
        // CE does not implement the assertEqual(x, x) comparison form.
        assert!(findings(&scan("case.assertEqual(a, a)\n"), "python:S5914").is_empty());
    }
}
