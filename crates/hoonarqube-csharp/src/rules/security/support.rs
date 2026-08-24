use crate::cst::{collect_kinds, is_error_tainted, node_text};
use crate::rules::literals::argument_nodes;
use tree_sitter::Node;

/// The declaration an attribute decorates (`attribute` → `attribute_list` →
/// declaration). Assembly-level attributes have no declaration.
pub(crate) fn attributed_declaration(attribute: Node<'_>) -> Option<Node<'_>> {
    attribute
        .parent()
        .filter(|list| list.kind() == "attribute_list")
        .and_then(|list| list.parent())
}

/// Return-type spelling of a callable (`void`, `Task<int>`, ...); the field
/// carrying it differs between declaration kinds.
pub(crate) fn return_type_text<'a>(callable: Node<'_>, source: &'a str) -> &'a str {
    for field in ["returns", "type"] {
        if let Some(return_type) = callable.child_by_field_name(field) {
            return node_text(return_type, source);
        }
    }
    ""
}

/// `argument` wrapper nodes of an invocation or object creation; the
/// wrappers live one level down inside the `argument_list`.
pub(crate) fn call_argument_nodes(call: Node<'_>) -> Vec<Node<'_>> {
    let mut cursor = call.walk();
    call.children(&mut cursor)
        .find(|child| child.kind() == "argument_list")
        .map(argument_nodes)
        .unwrap_or_default()
}

/// Identifier nodes spelling one of `names`, ignoring using directives where
/// the name merely imports a namespace.
pub(crate) fn identifier_usages<'t>(root: Node<'t>, source: &str, names: &[&str]) -> Vec<Node<'t>> {
    collect_kinds(root, &["identifier"])
        .into_iter()
        .filter(|node| !is_error_tainted(*node))
        .filter(|node| names.contains(&node_text(*node, source)))
        .filter(|node| {
            node.parent()
                .is_none_or(|parent| parent.kind() != "using_directive")
        })
        .collect()
}
