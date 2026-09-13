use crate::cst::{node_text, simple_name};
use tree_sitter::Node;
pub(crate) const TYPE_DECLARATION_KINDS: [&str; 5] = [
    "class_declaration",
    "interface_declaration",
    "struct_declaration",
    "record_declaration",
    "enum_declaration",
];

pub(crate) fn declaration_kind_word(kind: &str) -> &str {
    match kind {
        "class_declaration" => "class",
        "interface_declaration" => "interface",
        "struct_declaration" => "struct",
        "record_declaration" => "record",
        _ => "enum",
    }
}

pub(crate) fn has_explicit_interface_specifier(node: Node<'_>) -> bool {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .any(|child| child.kind() == "explicit_interface_specifier")
}

pub(crate) fn enum_has_flags_attribute(enum_node: Node<'_>, source: &str) -> bool {
    let mut list_cursor = enum_node.walk();
    enum_node
        .children(&mut list_cursor)
        .filter(|child| child.kind() == "attribute_list")
        .any(|list| {
            let mut attribute_cursor = list.walk();
            list.children(&mut attribute_cursor)
                .filter(|attribute| attribute.kind() == "attribute")
                .filter_map(|attribute| attribute.child_by_field_name("name"))
                .any(|name| simple_name(node_text(name, source)) == "Flags")
        })
}

/// Direct members of a type's `declaration_list` body (empty for positional
/// records and enums).
pub(crate) fn type_members(type_node: Node<'_>) -> Vec<Node<'_>> {
    let Some(body) = type_node.child_by_field_name("body") else {
        return Vec::new();
    };
    if body.kind() != "declaration_list" {
        return Vec::new();
    }
    let mut cursor = body.walk();
    body.children(&mut cursor).collect()
}

/// Fully qualified syntactic identity of a type declaration:
/// `namespace.outer.inner` with canonicalized identifiers. Partial
/// declarations of one type share this identity regardless of which file or
/// declaration carries them.
pub(crate) fn full_type_identity(type_node: Node<'_>, source: &str) -> Option<String> {
    let name = type_node.child_by_field_name("name")?;
    let mut path: Vec<String> = crate::cst::ancestors_of(type_node)
        .filter(|ancestor| TYPE_DECLARATION_KINDS.contains(&ancestor.kind()))
        .filter_map(|ancestor| ancestor.child_by_field_name("name"))
        .map(|ancestor| crate::cst::canonical_identifier(node_text(ancestor, source)).to_string())
        .collect();
    path.reverse();
    path.push(crate::cst::canonical_identifier(node_text(name, source)).to_string());
    let joined = path.join(".");
    let namespace = crate::cst::containing_namespace(type_node, source);
    Some(if namespace.is_empty() {
        joined
    } else {
        format!("{namespace}.{joined}")
    })
}
