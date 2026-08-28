use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3235 — parentheses around return values and arguments
/// cannot change precedence there and are noise.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if is_error_tainted(creation)
            || collect_kinds(creation, &["initializer_expression"]).is_empty()
        {
            continue;
        }
        let mut cursor = creation.walk();
        if let Some(arguments) = creation.children(&mut cursor).find(|child| {
            child.kind() == "argument_list" && node_text(*child, source).trim() == "()"
        }) {
            issues.push(issue(
                language,
                "S3235",
                "Remove these redundant parentheses.",
                range_of(arguments, source),
            ));
        }
    }
    for attribute in collect_kinds(root, &["attribute"]) {
        let mut cursor = attribute.walk();
        if let Some(arguments) = attribute.children(&mut cursor).find(|child| {
            child.kind() == "attribute_argument_list" && node_text(*child, source).trim() == "()"
        }) {
            issues.push(issue(
                language,
                "S3235",
                "Remove these redundant parentheses.",
                range_of(arguments, source),
            ));
        }
    }
    issues
}
