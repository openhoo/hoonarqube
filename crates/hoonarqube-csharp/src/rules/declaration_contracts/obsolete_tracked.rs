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
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1133_tracks_long_form_and_member_annotations() {
        let long_form = analyze_default("[ObsoleteAttribute]\nclass Old\n{\n}\n");
        assert_eq!(with_key(&long_form, "csharpsquid:S1133").len(), 1);

        let members = analyze_default(
            "class Old\n{\n    [Obsolete]\n    private int stale;\n\n    [Obsolete]\n    void Legacy() { }\n}\n",
        );
        assert_eq!(with_key(&members, "csharpsquid:S1133").len(), 2);
    }

    #[test]
    fn s1133_spares_live_members() {
        let fresh = analyze_default("[Serializable]\nclass Fresh\n{\n    void Keep() { }\n}\n");
        assert!(with_key(&fresh, "csharpsquid:S1133").is_empty());
    }
}
