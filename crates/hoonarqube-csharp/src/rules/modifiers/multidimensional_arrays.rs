use super::support::{field_declarators, field_type, is_multidimensional_array};
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3967 — declarations should expose jagged arrays instead of
/// multidimensional arrays. Array creation expressions are not declarations.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declaration in collect_kinds(
        root,
        &[
            "field_declaration",
            "property_declaration",
            "method_declaration",
            "parameter",
        ],
    ) {
        let type_node = declaration
            .child_by_field_name("returns")
            .or_else(|| declaration.child_by_field_name("type"))
            .or_else(|| field_type(declaration));
        let Some(type_node) = type_node else {
            continue;
        };
        if type_node.kind() != "array_type" || !is_multidimensional_array(type_node, source) {
            continue;
        }
        let anchors: Vec<Node<'_>> = if declaration.kind() == "field_declaration" {
            field_declarators(declaration)
                .into_iter()
                .filter_map(|declarator| declarator.child_by_field_name("name"))
                .collect()
        } else {
            declaration
                .child_by_field_name("name")
                .into_iter()
                .collect()
        };
        for anchor in anchors {
            issues.push(issue(
                language,
                "S3967",
                "Change this multidimensional array to a jagged array.",
                range_of(anchor, source),
            ));
        }
    }
    issues
}
