use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1199 — plain code blocks nest only through control flow.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for block in collect_kinds(root, &["block"]) {
        if is_error_tainted(block) {
            continue;
        }
        if block
            .parent()
            .is_some_and(|parent| parent.kind() == "block")
        {
            issues.push(issue(
                language,
                "S1199",
                "Remove this nested code block.",
                range_of(block),
            ));
        }
    }
    issues
}
