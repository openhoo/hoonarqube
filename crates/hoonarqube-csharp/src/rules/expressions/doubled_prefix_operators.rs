use super::support::first_named_child;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2761 — prefix operators do not double up.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for unary in collect_kinds(root, &["prefix_unary_expression"]) {
        if is_error_tainted(unary) || !matches!(operator_of(unary), Some("!" | "~" | "+" | "-")) {
            continue;
        }
        let doubled = first_named_child(unary).is_some_and(|operand| {
            operand.kind() == "prefix_unary_expression"
                && matches!(operator_of(operand), Some("!" | "~" | "+" | "-"))
        });
        if doubled {
            issues.push(issue(
                language,
                "S2761",
                "Collapse these doubled prefix operators.",
                range_of(unary, source),
            ));
        }
    }
    issues
}
