use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4061 — `params` replaced `__arglist` long ago.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for identifier in collect_kinds(root, &["identifier"]) {
        if node_text(identifier, source) == "__arglist" {
            issues.push(issue(
                language,
                "S4061",
                "Use 'params' instead of '__arglist'.",
                range_of(identifier),
            ));
        }
    }
    issues
}
