use super::support::boolean_literal_side;
use super::support::comparisons;
use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3240 — conditions use their simplest shape: negation beats
/// comparing against `false`, ternaries over boolean literals collapse to
/// their condition.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        let literal = boolean_literal_side(left, right, source);
        let simplifiable = matches!(
            (operator_of(expression), literal),
            (Some("=="), Some(false)) | (Some("!="), Some(true))
        );
        if simplifiable {
            issues.push(issue(
                language,
                "S3240",
                "Replace this comparison with a negation of its operand.",
                range_of(expression),
            ));
        }
    }
    for conditional in collect_kinds(root, &["conditional_expression"]) {
        if is_error_tainted(conditional) {
            continue;
        }
        let mut cursor = conditional.walk();
        let branches: Vec<Node> = conditional
            .children(&mut cursor)
            .filter(tree_sitter::Node::is_named)
            .skip(1)
            .collect();
        if branches.len() == 2 && branches.iter().all(|b| b.kind() == "boolean_literal") {
            issues.push(issue(
                language,
                "S3240",
                "Replace this ternary with its condition directly.",
                range_of(conditional),
            ));
        }
    }
    issues
}
