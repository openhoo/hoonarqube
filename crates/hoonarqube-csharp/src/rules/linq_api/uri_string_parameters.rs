use super::support::methods_grouped_by_name;
use crate::CsLanguage;
use crate::cst::{issue, node_text, parameters_of, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3994 — string parameters duplicating a sibling `System.Uri`
/// overload push conversion work onto callers.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for methods in methods_grouped_by_name(root, source).into_values() {
        if methods.len() < 2 {
            continue;
        }
        let shapes: Vec<Vec<String>> = methods
            .iter()
            .map(|method| {
                parameters_of(*method)
                    .iter()
                    .filter_map(|parameter| parameter.child_by_field_name("type"))
                    .map(|type_node| simple_name(node_text(type_node, source)).to_string())
                    .collect()
            })
            .collect();
        for index in 0..shapes.iter().map(Vec::len).max().unwrap_or(0) {
            let has_uri = shapes
                .iter()
                .any(|shape| shape.get(index).is_some_and(|name| name == "Uri"));
            if !has_uri {
                continue;
            }
            for (method, shape) in methods.iter().zip(&shapes) {
                if shape.get(index).is_some_and(|name| name == "string") {
                    issues.push(issue(
                        language,
                        "S3994",
                        "Accept a 'System.Uri' instead of a string here.",
                        range_of(*method),
                    ));
                }
            }
        }
    }
    issues
}
