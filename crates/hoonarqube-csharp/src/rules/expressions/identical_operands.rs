use super::support::binary_operands;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1764 — identical sub-expressions on both sides of an
/// arithmetic or relational operator.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expression in collect_kinds(root, &["binary_expression"]) {
        if is_error_tainted(expression) {
            continue;
        }
        let Some(operator) = operator_of(expression) else {
            continue;
        };
        let Some((left, right)) = binary_operands(expression) else {
            continue;
        };
        if IDENTICAL_OPERAND_OPERATORS.contains(&operator)
            && !node_text(left, source).is_empty()
            && node_text(left, source) == node_text(right, source)
        {
            issues.push(issue(
                language,
                "S1764",
                "Identical sub-expressions are used on both sides of this operator.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// Operators whose identical operands betray a bug (`a * a` may be intended,
/// `a - a` never is).
const IDENTICAL_OPERAND_OPERATORS: [&str; 7] = ["-", "/", "%", "<", ">", "<=", ">="];
