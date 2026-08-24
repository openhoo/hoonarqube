use crate::cst::{collect_kinds, node_text, simple_name};
use crate::rules::modifiers::type_parameter_list_of;
use tree_sitter::Node;

/// Unconstrained generic parameter names of one declaration.
pub(crate) fn unconstrained_generic_parameters(
    declaration: Node<'_>,
    source: &str,
) -> Option<std::collections::HashSet<String>> {
    let (list, _) = type_parameter_list_of(declaration)?;
    let mut unconstrained: std::collections::HashSet<String> = collect_kinds(list, &["identifier"])
        .into_iter()
        .map(|identifier| node_text(identifier, source).to_string())
        .collect();
    if unconstrained.is_empty() {
        return None;
    }
    let mut cursor = declaration.walk();
    for child in declaration.children(&mut cursor) {
        if child.kind() != "type_parameter_constraints_clause" {
            continue;
        }
        let clause = node_text(child, source);
        if let Some((head, tail)) = clause.split_once(':') {
            let constrained = tail
                .split(',')
                .map(str::trim)
                .filter_map(|bound| bound.split_whitespace().next())
                .any(|bound| matches!(bound, "class" | "struct" | "notnull"));
            if !constrained {
                continue;
            }
            let Some(name) = head.split_whitespace().last() else {
                continue;
            };
            unconstrained.remove(name);
        }
    }
    (!unconstrained.is_empty()).then_some(unconstrained)
}

/// Explicitly typed variables as `(name, declared simple type)` pairs.
pub(crate) fn typed_variables<'a>(root: Node<'a>, source: &'a str) -> Vec<(&'a str, &'a str)> {
    collect_kinds(root, &["variable_declarator"])
        .into_iter()
        .filter_map(|declarator| {
            let name = declarator.child_by_field_name("name")?;
            let declaration = declarator.parent()?;
            let type_node = declaration.child_by_field_name("type")?;
            Some((
                node_text(name, source),
                simple_name(node_text(type_node, source)),
            ))
        })
        .collect()
}
