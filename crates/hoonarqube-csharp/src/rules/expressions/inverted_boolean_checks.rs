use super::support::first_named_child;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1940 — negated equality flips into the opposite operator.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for unary in collect_kinds(root, &["prefix_unary_expression"]) {
        if is_error_tainted(unary) || operator_of(unary) != Some("!") {
            continue;
        }
        let invertible = first_named_child(unary).is_some_and(|operand| {
            operand.kind() == "parenthesized_expression"
                && first_named_child(operand).is_some_and(|inner| {
                    inner.kind() == "binary_expression"
                        && matches!(operator_of(inner), Some("==" | "!="))
                })
        });
        if invertible {
            issues.push(issue(
                language,
                "S1940",
                "Invert this comparison instead of negating it.",
                range_of(unary),
            ));
        }
    }
    issues
}
