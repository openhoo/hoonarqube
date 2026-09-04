use super::support::assembly_attribute_names;
use super::support::file_level_issue;
use crate::CsLanguage;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Assembly-annotation presence checks (csharpsquid:S3990, S3992, S4026).
/// Files without any assembly attributes are not treated as assembly-info
/// files and stay clean; a file annotating some but not all of the trio is
/// flagged for the missing ones.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let names = assembly_attribute_names(root, source);
    if names.is_empty() {
        return Vec::new();
    }
    let has = |wanted: &[&str]| names.iter().any(|name| wanted.contains(name));
    let mut issues = Vec::new();
    if !has(&["CLSCompliant", "CLSCompliantAttribute"]) {
        issues.push(file_level_issue(
            language,
            "S3990",
            "Annotate this assembly with '[assembly: CLSCompliant]'.",
        ));
    }
    if !has(&["ComVisible", "ComVisibleAttribute"]) {
        issues.push(file_level_issue(
            language,
            "S3992",
            "Annotate this assembly with '[assembly: ComVisible]'.",
        ));
    }
    if !has(&[
        "NeutralResourcesLanguage",
        "NeutralResourcesLanguageAttribute",
    ]) {
        issues.push(file_level_issue(
            language,
            "S4026",
            "Annotate this assembly with '[assembly: NeutralResourcesLanguage]'.",
        ));
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn assembly_annotation_rules_ignore_module_only_attributes() {
        let module_only = analyze_default(
            "[module: System.ComVisible(false)]\n\n// This type is unrelated to assembly metadata.\nclass C { }\n",
        );
        for key in [
            "csharpsquid:S3990",
            "csharpsquid:S3992",
            "csharpsquid:S4026",
        ] {
            assert!(
                with_key(&module_only, key).is_empty(),
                "module metadata must not satisfy or trigger {key}",
            );
        }

        let mixed = analyze_default(
            "[module: System.ComVisible(false)]\n[assembly: System.CLSCompliant(true)]\nclass C { }\n",
        );
        assert!(with_key(&mixed, "csharpsquid:S3990").is_empty());
        assert_eq!(with_key(&mixed, "csharpsquid:S3992").len(), 1);
        assert_eq!(with_key(&mixed, "csharpsquid:S4026").len(), 1);
    }
}
