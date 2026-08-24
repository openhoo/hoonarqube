use super::support::child_operator;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::binary_operands;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3244 — a fresh anonymous delegate never equals the one that
/// subscribed, so the handler stays attached.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["assignment_expression"])
        .into_iter()
        .filter(|assignment| !is_error_tainted(*assignment))
        .filter(|assignment| child_operator(*assignment, source) == Some("-="))
        .filter(|assignment| {
            binary_operands(*assignment).is_some_and(|(_, value)| {
                matches!(
                    value.kind(),
                    "lambda_expression" | "anonymous_method_expression"
                )
            })
        })
        .map(|assignment| {
            issue(
                language,
                "S3244",
                "Unsubscribe with the original delegate, not a new anonymous one.",
                range_of(assignment),
            )
        })
        .collect()
}
