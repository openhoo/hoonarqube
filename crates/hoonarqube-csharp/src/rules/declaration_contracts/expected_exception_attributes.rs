use super::support::attribute_applications;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3431 — `MSTest`'s `ExpectedException` hides which assertion
/// failed; assertions inside the test report precisely.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, _, node) in attribute_applications(root, source) {
        if matches!(name, "ExpectedException" | "ExpectedExceptionAttribute") {
            issues.push(issue(
                language,
                "S3431",
                "Replace this 'ExpectedException' annotation with assertions.",
                range_of(node),
            ));
        }
    }
    issues
}
