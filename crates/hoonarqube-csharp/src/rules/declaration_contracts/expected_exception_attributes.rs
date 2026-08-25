use super::support::tracked_attribute_issues;
use crate::CsLanguage;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3431 — `MSTest`'s `ExpectedException` hides which assertion
/// failed; assertions inside the test report precisely.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    tracked_attribute_issues(
        root,
        source,
        language,
        &["ExpectedException", "ExpectedExceptionAttribute"],
        "S3431",
        "Replace this 'ExpectedException' annotation with assertions.",
    )
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
