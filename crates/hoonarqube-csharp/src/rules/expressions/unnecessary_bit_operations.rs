use super::support::binary_operands;
use super::support::first_named_child;
use super::support::is_zero_literal;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2437 — bit operations fold away when an operand makes them
/// constants.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        let zero_on_either = is_zero_literal(left, source) || is_zero_literal(right, source);
        let minus_one_on_either = is_negative_one(left, source) || is_negative_one(right, source);
        let identical = node_text(left, source).trim() == node_text(right, source).trim();
        let verdict = match operator_of(expression) {
            Some("&") if zero_on_either => Some("'and' with zero always yields zero."),
            Some("|") if minus_one_on_either => Some("'or' with -1 always yields -1."),
            Some("|") if zero_on_either => Some("'or' with zero changes nothing."),
            Some("^") if identical => Some("'xor' of identical operands always yields zero."),
            _ => None,
        };
        if let Some(verdict) = verdict {
            issues.push(issue(
                language,
                "S2437",
                format!("Remove this unnecessary bit operation: {verdict}"),
                range_of(expression, source),
            ));
        }
    }
    issues
}

/// `-1`: a negated unit literal.
fn is_negative_one(operand: Node<'_>, source: &str) -> bool {
    operand.kind() == "prefix_unary_expression"
        && operator_of(operand) == Some("-")
        && first_named_child(operand).is_some_and(|literal| node_text(literal, source) == "1")
}
