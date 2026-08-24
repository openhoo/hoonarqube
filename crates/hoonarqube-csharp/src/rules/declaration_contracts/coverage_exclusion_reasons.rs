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
