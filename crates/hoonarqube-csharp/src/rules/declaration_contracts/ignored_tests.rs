use super::support::tracked_attribute_issues;
use crate::CsLanguage;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1607 — ignored tests silently stop guarding behavior.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    tracked_attribute_issues(
        root,
        source,
        language,
        &["Ignore", "IgnoreAttribute"],
        "S1607",
        "Remove this 'Ignore' annotation and fix the test.",
    )
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1607_flags_long_form_ignore_annotations() {
        let report =
            analyze_default("class Suite\n{\n    [IgnoreAttribute]\n    void T() { }\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S1607").len(), 1);

        let categorized =
            analyze_default("class Suite\n{\n    [Category(\"slow\")]\n    void T() { }\n}\n");
        assert!(with_key(&categorized, "csharpsquid:S1607").is_empty());
    }

    #[test]
    fn s1607_counts_reasoned_and_multiple_ignores() {
        let report = analyze_default(
            "class Suite\n{\n    [Ignore(\"flaky\")]\n    void A() { }\n\n    [Ignore]\n    void B() { }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1607").len(), 2);
    }
}
