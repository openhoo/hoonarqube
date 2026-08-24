use super::support::comparisons;
use super::support::expression_name;
use super::support::first_named_child;
use super::support::integer_literal_value;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3981 — collection sizes never compare against negatives.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    fn negative_value(operand: Node<'_>, source: &str) -> Option<i64> {
        if operand.kind() != "prefix_unary_expression" || operator_of(operand) != Some("-") {
            return None;
        }
        let literal = first_named_child(operand)?;
        integer_literal_value(node_text(literal, source))
            .and_then(|value| i64::try_from(value).ok())
            .map(|value| -value)
    }
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        let size_side = [left, right].iter().any(|o| count_member_tail(*o, source));
        let negative_side = [left, right]
            .iter()
            .any(|o| negative_value(*o, source).is_some());
        if size_side && negative_side {
            issues.push(issue(
                language,
                "S3981",
                "Collection sizes are never negative; fix this comparison.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// Collection-count member tails (`Count`, `Length`).
fn count_member_tail(operand: Node<'_>, source: &str) -> bool {
    matches!(expression_name(operand, source), Some("Count" | "Length"))
}
