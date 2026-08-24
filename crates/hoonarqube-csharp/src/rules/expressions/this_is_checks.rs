use super::support::first_named_child;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3060 — 'this' does not take part in 'is' type tests.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for is_expression in collect_kinds(root, &["is_expression"]) {
        if is_error_tainted(is_expression) {
            continue;
        }
        let tests_this = first_named_child(is_expression)
            .is_some_and(|operand| node_text(operand, source) == "this");
        if tests_this {
            issues.push(issue(
                language,
                "S3060",
                "Do not combine 'this' with the 'is' operator.",
                range_of(is_expression),
            ));
        }
    }
    issues
}
