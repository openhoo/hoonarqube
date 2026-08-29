use crate::cst::{attributes_of, collect_kinds, modifiers_of, node_text, simple_name, to_u32};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use tree_sitter::Node;

/// Whether one keyword (`public`, `static`, `const`, …) is in `modifiers`.
pub(crate) fn has_modifier(modifiers: &[&str], wanted: &str) -> bool {
    modifiers.contains(&wanted)
}

pub(crate) fn has_any_accessibility(modifiers: &[&str]) -> bool {
    modifiers
        .iter()
        .any(|modifier| matches!(*modifier, "public" | "private" | "protected" | "internal"))
}

/// C# accessibility ladder: private < private protected < internal <
/// protected < protected internal < public. Undeclared ranks lowest; use
/// [`type_declared_rank`] for type declarations, where C# defaults differ.
pub(crate) fn accessibility_rank(modifiers: &[&str]) -> u8 {
    let has = |wanted: &str| has_modifier(modifiers, wanted);
    if has("public") {
        6
    } else if has("protected") && has("internal") {
        5
    } else if has("private") && has("protected") {
        2
    } else if has("protected") {
        4
    } else if has("internal") {
        3
    } else {
        1
    }
}

/// Declared rank of a *type* declaration, applying C# defaults: nested types
/// are private, types outside any other type are internal.
pub(crate) fn type_declared_rank(type_node: Node<'_>, source: &str) -> u8 {
    let modifiers = modifiers_of(type_node, source);
    if has_any_accessibility(&modifiers) {
        return accessibility_rank(&modifiers);
    }
    let mut ancestor = type_node.parent();
    while let Some(node) = ancestor {
        if TYPE_DECLARATION_KINDS.contains(&node.kind()) {
            return 1;
        }
        ancestor = node.parent();
    }
    3
}

pub(crate) fn has_attribute(names: &[&str], wanted: &str) -> bool {
    names.contains(&wanted)
}

pub(crate) fn has_any_attribute(node: Node<'_>, source: &str, wanted: &[&str]) -> bool {
    wanted
        .iter()
        .any(|name| has_attribute(&attributes_of(node, source), name))
}

/// Direct attribute node with a matching simple name. Qualification and the
/// optional `Attribute` suffix are normalized the same way as `attributes_of`.
pub(crate) fn attribute_named<'a>(node: Node<'a>, source: &str, wanted: &str) -> Option<Node<'a>> {
    let mut node_cursor = node.walk();
    for list in node
        .children(&mut node_cursor)
        .filter(|child| child.kind() == "attribute_list")
    {
        let mut list_cursor = list.walk();
        for attribute in list
            .children(&mut list_cursor)
            .filter(|child| child.kind() == "attribute")
        {
            let Some(name) = attribute.child_by_field_name("name") else {
                continue;
            };
            let simple = simple_name(node_text(name, source));
            if simple.strip_suffix("Attribute").unwrap_or(simple) == wanted {
                return Some(attribute);
            }
        }
    }
    None
}

pub(crate) fn subtree_contains_kind(root: Node<'_>, kind: &str) -> bool {
    !collect_kinds(root, &[kind]).is_empty()
}

/// True for multi-dimensional arrays (`int[,]`); jagged arrays are nested
/// `array_type`s and never match.
pub(crate) fn is_multidimensional_array(array_type_node: Node<'_>, source: &str) -> bool {
    array_type_node
        .child_by_field_name("rank")
        .is_some_and(|rank| node_text(rank, source).contains(','))
}

pub(crate) fn has_ancestor_with_kind(mut node: Node<'_>, kinds: &[&str]) -> bool {
    while let Some(parent) = node.parent() {
        if kinds.contains(&parent.kind()) {
            return true;
        }
        node = parent;
    }
    false
}

/// A declaration's `type_parameter_list` together with its arity.
pub(crate) fn type_parameter_list_of(declaration: Node<'_>) -> Option<(Node<'_>, u32)> {
    let mut cursor = declaration.walk();
    let list = declaration
        .children(&mut cursor)
        .find(|child| child.kind() == "type_parameter_list")?;
    let mut list_cursor = list.walk();
    let count = to_u32(
        list.children(&mut list_cursor)
            .filter(|child| child.kind() == "type_parameter")
            .count(),
    );
    Some((list, count))
}

/// Direct declarators of a field/event declaration. Descendant collection is
/// deliberately avoided because an initializer can contain a lambda with its
/// own local variable declarations.
pub(crate) fn field_declarators(declaration: Node<'_>) -> Vec<Node<'_>> {
    let mut declaration_cursor = declaration.walk();
    let Some(variables) = declaration
        .children(&mut declaration_cursor)
        .find(|child| child.kind() == "variable_declaration")
    else {
        return Vec::new();
    };
    let mut variable_cursor = variables.walk();
    variables
        .children(&mut variable_cursor)
        .filter(|child| child.kind() == "variable_declarator")
        .collect()
}

/// Direct type node of a field/event declaration.
pub(crate) fn field_type(declaration: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = declaration.walk();
    declaration
        .children(&mut cursor)
        .find(|child| child.kind() == "variable_declaration")
        .and_then(|variables| variables.child_by_field_name("type"))
}
