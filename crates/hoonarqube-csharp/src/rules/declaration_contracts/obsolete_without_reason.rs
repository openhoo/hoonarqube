use super::support::attribute_applications;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1123 — `[Obsolete]` without an explanation leaves future
/// maintainers guessing.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, args, node) in attribute_applications(root, source) {
        if matches!(name, "Obsolete" | "ObsoleteAttribute") && args.is_none() {
            issues.push(issue(
                language,
                "S1123",
                "Document why this code is obsolete with an explanation message.",
                range_of(node),
            ));
        }
    }
    issues
}
