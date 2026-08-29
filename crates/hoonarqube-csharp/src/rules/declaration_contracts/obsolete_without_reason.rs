use super::support::{attribute_applications, has_attribute_explanation};
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1123 — `[Obsolete]` without an explanation leaves future
/// maintainers guessing.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, args, node) in attribute_applications(root, source) {
        if matches!(name, "Obsolete" | "ObsoleteAttribute")
            && !has_attribute_explanation(args, source)
        {
            issues.push(issue(
                language,
                "S1123",
                "Add an explanation.",
                range_of(node, source),
            ));
        }
    }
    issues
}
#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s1123_flags_long_form_without_arguments() {
        let report = analyze_default("[ObsoleteAttribute]\nclass Old\n{\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S1123").len(), 1);
    }

    #[test]
    fn s1123_counts_only_reasonless_member_annotations() {
        let bare = analyze_default(
            "class Old\n{\n    [Obsolete]\n    void A() { }\n\n    [Obsolete]\n    int B() => 1;\n}\n",
        );
        assert_eq!(with_key(&bare, "csharpsquid:S1123").len(), 2);

        let explained = analyze_default(
            "class Old\n{\n    [Obsolete(\"use C\")]\n    void A() { }\n\n    [Obsolete(\"use D\")]\n    int B() => 1;\n}\n",
        );
        assert!(with_key(&explained, "csharpsquid:S1123").is_empty());
    }

    #[test]
    fn s1123_rejects_empty_and_null_explanations() {
        for source in [
            "[Obsolete()]\nclass Old { }\n",
            "[Obsolete(\"\")]\nclass Old { }\n",
            "[Obsolete(null)]\nclass Old { }\n",
        ] {
            let report = analyze_default(source);
            assert_eq!(with_key(&report, "csharpsquid:S1123").len(), 1);
        }
    }
}
