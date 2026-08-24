use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1110 — a parenthesis pair wrapping only another pair is
/// redundant.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for parenthesized in collect_kinds(root, &["parenthesized_expression"]) {
        if is_error_tainted(parenthesized) {
            continue;
        }
        let mut cursor = parenthesized.walk();
        let wraps_single_pair = parenthesized.named_child_count() == 1
            && parenthesized
                .children(&mut cursor)
                .all(|child| !child.is_named() || child.kind() == "parenthesized_expression");
        if wraps_single_pair {
            issues.push(issue(
                language,
                "S1110",
                "Remove this redundant pair of parentheses.",
                range_of(parenthesized),
            ));
        }
    }
    issues
}
