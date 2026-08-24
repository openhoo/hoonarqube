use super::support::binary_operands;
use super::support::integer_literal_value;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2183 — shift amounts stay within 1..31 for 32-bit operands.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression)
            || !matches!(operator_of(expression), Some("<<" | ">>" | ">>>"))
        {
            continue;
        }
        let Some((_, right)) = binary_operands(expression) else {
            continue;
        };
        if right.kind() != "integer_literal" {
            continue;
        }
        let Some(amount) = integer_literal_value(node_text(right, source)) else {
            continue;
        };
        if amount == 0 || amount >= 32 {
            issues.push(issue(
                language,
                "S2183",
                format!(
                    "Shift by a non-zero amount below the operand width ({amount} is out of range)."
                ),
                range_of(expression),
            ));
        }
    }
    issues
}
