use super::support::is_event_handler_shape;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3908 — custom delegates shaped like `(object, EventArgs)`
/// duplicate `EventHandler<T>`; use the framework type.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let handler_shapes: std::collections::HashSet<&str> =
        collect_kinds(root, &["delegate_declaration"])
            .into_iter()
            .filter(|delegate| is_event_handler_shape(*delegate, source))
            .filter_map(|delegate| delegate.child_by_field_name("name"))
            .map(|name_node| node_text(name_node, source))
            .collect();
    if handler_shapes.is_empty() {
        return Vec::new();
    }
    collect_kinds(root, &["event_field_declaration"])
        .into_iter()
        .flat_map(|event_field| collect_kinds(event_field, &["variable_declaration"]))
        .filter(|declaration| {
            declaration
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    handler_shapes.contains(simple_name(node_text(type_node, source)))
                })
        })
        .flat_map(|declaration| collect_kinds(declaration, &["variable_declarator"]))
        .filter_map(|declarator| declarator.child_by_field_name("name"))
        .map(|name_node| {
            issue(
                language,
                "S3908",
                format!(
                    "Use 'EventHandler<T>' instead of this custom delegate for '{}'.",
                    node_text(name_node, source)
                ),
                range_of(name_node),
            )
        })
        .collect()
}
