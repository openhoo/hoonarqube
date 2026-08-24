use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{binary_operands, operator_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2589 — boolean literals next to a short-circuit operator
/// change nothing about the result. Comparisons against literals and
/// doubled negations are covered by S1125 and S2761 instead.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) || !matches!(operator_of(expression), Some("&&" | "||")) {
            continue;
        }
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        for operand in [left, right] {
            if operand.kind() == "boolean_literal" {
                issues.push(issue(
                    language,
                    "S2589",
                    "This boolean literal is gratuitous in a short-circuit operation.",
                    range_of(operand),
                ));
            }
        }
    }
    issues
}
