use super::support::attribute_applications;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1133 — uses of `[Obsolete]` are tracked so deprecated code
/// eventually gets removed.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, _, node) in attribute_applications(root, source) {
        if matches!(name, "Obsolete" | "ObsoleteAttribute") {
            issues.push(issue(
                language,
                "S1133",
                "Deprecated code should be removed.",
                range_of(node),
            ));
        }
    }
    issues
}
