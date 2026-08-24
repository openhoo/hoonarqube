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
