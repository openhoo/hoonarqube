use super::support::attribute_applications;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1607 — ignored tests silently stop guarding behavior.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, _, node) in attribute_applications(root, source) {
        if matches!(name, "Ignore" | "IgnoreAttribute") {
            issues.push(issue(
                language,
                "S1607",
                "Remove this 'Ignore' annotation and fix the test.",
                range_of(node),
            ));
        }
    }
    issues
}
