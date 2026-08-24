use super::support::comparisons;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2197 — remainders compare against ranges, not values.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    fn modulus(operand: Node<'_>) -> bool {
        operand.kind() == "binary_expression" && operator_of(operand) == Some("%")
    }
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        if matches!(operator_of(expression), Some("==" | "!=")) && (modulus(left) || modulus(right))
        {
            issues.push(issue(
                language,
                "S2197",
                "Compare remainder results against ranges, not single values.",
                range_of(expression),
            ));
        }
    }
    issues
}
