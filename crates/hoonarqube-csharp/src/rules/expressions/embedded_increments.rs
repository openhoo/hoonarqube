use super::support::operator_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S881 — increments and decrements stay standalone.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    const KINDS: [&str; 2] = ["prefix_unary_expression", "postfix_unary_expression"];
    let mut issues = Vec::new();
    for unary in collect_kinds(root, &KINDS) {
        if is_error_tainted(unary) || !matches!(operator_of(unary), Some("++" | "--")) {
            continue;
        }
        let parent_kind = unary.parent().map(|parent| parent.kind());
        if matches!(parent_kind, Some("expression_statement" | "for_statement")) {
            continue;
        }
        issues.push(issue(
            language,
            "S881",
            "Extract this increment or decrement into its own statement.",
            range_of(unary),
        ));
    }
    issues
}
