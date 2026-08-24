use super::support::attribute_applications;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1309 — in-source suppressions are tracked so they stay rare
/// and deliberate.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, _, node) in attribute_applications(root, source) {
        if matches!(name, "SuppressMessage" | "SuppressMessageAttribute") {
            issues.push(issue(
                language,
                "S1309",
                "Track uses of in-source suppressions.",
                range_of(node),
            ));
        }
    }
    for pragma in collect_kinds(root, &["preproc_pragma"]) {
        if !is_error_tainted(pragma) && node_text(pragma, source).contains("warning disable") {
            issues.push(issue(
                language,
                "S1309",
                "Track uses of in-source suppressions.",
                range_of(pragma),
            ));
        }
    }
    issues
}
