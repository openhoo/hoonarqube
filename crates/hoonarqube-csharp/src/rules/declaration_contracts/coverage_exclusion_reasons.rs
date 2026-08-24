use super::support::attribute_applications;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6513 — coverage exclusions need a justification string.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, args, node) in attribute_applications(root, source) {
        let justified = args.is_some_and(|args| {
            collect_kinds(args, &["string_literal"])
                .iter()
                .any(|literal| node_text(*literal, source).len() > 2)
        });
        if matches!(
            name,
            "ExcludeFromCodeCoverage" | "ExcludeFromCodeCoverageAttribute"
        ) && !justified
        {
            issues.push(issue(
                language,
                "S6513",
                "Document the reason for excluding this code from coverage.",
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
    fn s6513_long_attribute_name_and_empty_reason_still_flag() {
        let long_name =
            analyze_default("[ExcludeFromCodeCoverageAttribute]\nclass Generated\n{\n}\n");
        assert_eq!(with_key(&long_name, "csharpsquid:S6513").len(), 1);

        let empty_reason =
            analyze_default("[ExcludeFromCodeCoverage(\"\")]\nclass Generated\n{\n}\n");
        assert_eq!(with_key(&empty_reason, "csharpsquid:S6513").len(), 1);
    }

    #[test]
    fn s6513_other_attributes_are_out_of_scope() {
        let report = analyze_default("[Obsolete(\"dead code\")]\nclass Legacy\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S6513").is_empty());
    }
}
