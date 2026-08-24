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

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3431_long_attribute_name_still_flags() {
        let report = analyze_default(
            "[ExpectedExceptionAttribute(typeof(System.Exception))]\nvoid T() { }\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3431").len(), 1);
    }

    #[test]
    fn s3431_similar_but_different_attributes_stay_unflagged() {
        let report = analyze_default("[ExpectException(typeof(System.Exception))]\nvoid T() { }\n");
        assert!(with_key(&report, "csharpsquid:S3431").is_empty());
    }
}
