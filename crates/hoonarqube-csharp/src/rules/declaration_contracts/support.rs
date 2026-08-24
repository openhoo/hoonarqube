use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, node_text};
use crate::rules::expressions::{
    first_named_child, member_declarations_of_kind, overloaded_operator,
};
use tree_sitter::Node;

/// Every attribute application in the file as `(simple name, argument list,
/// attribute node)`, assembly-level ones included.
pub(crate) fn attribute_applications<'t, 's>(
    root: Node<'t>,
    source: &'s str,
) -> Vec<(&'s str, Option<Node<'t>>, Node<'t>)> {
    collect_kinds(root, &["attribute"])
        .into_iter()
        .filter(|node| !is_error_tainted(*node))
        .filter_map(|node| {
            let mut cursor = node.walk();
            let named: Vec<Node> = node
                .children(&mut cursor)
                .filter(tree_sitter::Node::is_named)
                .collect();
            let name = first_named_child(node).map(|name| node_text(name, source))?;
            Some((name, named.get(1).copied(), node))
        })
        .collect()
}

/// The `operator_declaration` overloading `token`, if any.
pub(crate) fn operator_declaration_for<'t>(type_node: Node<'t>, token: &str) -> Option<Node<'t>> {
    member_declarations_of_kind(type_node, "operator_declaration")
        .into_iter()
        .find(|declaration| overloaded_operator(*declaration) == Some(token))
}

/// The nearest enclosing method declaration, if any.
pub(crate) fn enclosing_method(node: Node<'_>) -> Option<Node<'_>> {
    ancestors_of(node).find(|ancestor| ancestor.kind() == "method_declaration")
}
