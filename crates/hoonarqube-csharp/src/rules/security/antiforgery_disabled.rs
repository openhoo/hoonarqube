use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{binary_operands, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4502 — turning antiforgery off invites cross-site request
/// forgery.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["assignment_expression"])
        .into_iter()
        .filter(|assignment| !is_error_tainted(*assignment))
        .filter(|assignment| operator_of(*assignment) == Some("="))
        .filter(|assignment| {
            binary_operands(*assignment).is_some_and(|(target, value)| {
                node_text(target, source)
                    .to_ascii_lowercase()
                    .contains("ntiforgery")
                    && value.kind() == "boolean_literal"
                    && node_text(value, source) == "false"
            })
        })
        .map(|assignment| {
            issue(
                language,
                "S4502",
                "Keep antiforgery validation enabled.",
                range_of(assignment, source),
            )
        })
        .collect()
}
