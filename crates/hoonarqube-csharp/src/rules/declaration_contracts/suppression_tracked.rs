use super::support::tracked_attribute_issues;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1309 — in-source suppressions are tracked so they stay rare
/// and deliberate.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = tracked_attribute_issues(
        root,
        source,
        language,
        &["SuppressMessage", "SuppressMessageAttribute"],
        "S1309",
        "Track uses of in-source suppressions.",
    );
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
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1309_tracks_long_form_attributes() {
        let report = analyze_default(
            "[SuppressMessageAttribute(\"Category\", \"CheckId\")]\nclass A\n{\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S1309").len(), 1);
    }

    #[test]
    fn s1309_spares_restore_pragmas() {
        let report =
            analyze_default("class A\n{\n#pragma warning restore CS1234\n    void M() { }\n}\n");
        assert!(with_key(&report, "csharpsquid:S1309").is_empty());
    }

    #[test]
    fn s1309_accumulates_attribute_and_pragma_suppressions() {
        let combined = analyze_default(
            "[SuppressMessage(\"Category\", \"CheckId\")]\nclass A\n{\n    void M()\n    {\n#pragma warning disable CS1234, CS5679\n        Risky();\n    }\n}\n",
        );
        assert_eq!(with_key(&combined, "csharpsquid:S1309").len(), 2);
    }
}
