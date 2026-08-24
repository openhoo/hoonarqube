use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{binary_operands, callee_name, expression_name, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1155 — emptiness is what `Any()` expresses.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) {
            continue;
        }
        let Some(operator) = operator_of(expression) else {
            continue;
        };
        if operator != "==" && operator != "<=" {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        let zero = |operand: Node<'_>| {
            operand.kind() == "integer_literal" && node_text(operand, source) == "0"
        };
        if (is_count_expression(left, source) && zero(right))
            || (zero(left) && is_count_expression(right, source))
        {
            issues.push(issue(
                language,
                "S1155",
                "Use 'Any()' instead of comparing a count with zero.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// Whether the operand reads a collection size (`.Count()` / `.Count`).
fn is_count_expression(operand: Node<'_>, source: &str) -> bool {
    match operand.kind() {
        "invocation_expression" => callee_name(operand, source) == Some("Count"),
        "member_access_expression" => expression_name(operand, source) == Some("Count"),
        _ => false,
    }
}
