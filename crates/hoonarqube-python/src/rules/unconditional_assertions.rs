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
        if let Some(verdict) = unconditional_assert_verdict(call, source) {
            issues.push(issue_at(
                "python:S5914",
                &format!("This assertion always {verdict}."),
                call.range(),
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
        assert_eq!(findings(&flagged, "python:S5914").len(), 2);
        // CE does not implement the assertEqual(x, x) comparison form.
        assert!(findings(&scan("case.assertEqual(a, a)\n"), "python:S5914").is_empty());
    }
}
