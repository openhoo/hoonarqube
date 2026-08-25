use crate::engine::file_context::FileContext;
use crate::support::COMPARISON_ASSERTS;
use crate::support::assertion_literal_kind;
use crate::support::called_name;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5845 — assertions on incompatible literal types -------------------

pub(crate) fn check_incompatible_assert_literals(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for call in &file_ctx.calls {
        if called_name(&call.func).is_some_and(|name| COMPARISON_ASSERTS.contains(&name))
            && let [left, right] = &call.arguments.args[..]
            && let (Some(left_kind), Some(right_kind)) =
                (assertion_literal_kind(left), assertion_literal_kind(right))
            && left_kind != right_kind
        {
            issues.push(issue_at(
                "python:S5845",
                "This assertion compares literals of different types.",
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
    fn s5845_flags_incompatible_assert_literal_types() {
        let flagged = scan(
            "case.assertEqual(\"1\", 2)\ncase.assertEqual(1, 2)\ncase.assertEqual(\"1\", \"2\")\n",
        );
        assert_eq!(findings(&flagged, "python:S5845").len(), 1);
    }
}
