use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, modifiers_of, node_text, simple_name,
};
use crate::rules::expressions::{first_named_child, member_declarations_of_kind};
use crate::rules::modifiers::has_modifier;
use tree_sitter::Node;

/// Predefined integral type names.
pub(crate) const INTEGER_TYPES: [&str; 10] = [
    "int", "uint", "long", "ulong", "short", "ushort", "byte", "sbyte", "nint", "nuint",
];

/// Predefined floating-point type names (`Half` included).
pub(crate) const FLOATING_TYPES: [&str; 4] = ["float", "double", "decimal", "Half"];

/// Element expressions of an explicit, implicit, or collection-style array
/// literal.
fn collection_element_expressions(expression: Node<'_>) -> Vec<Node<'_>> {
    match expression.kind() {
        "array_creation_expression" | "implicit_array_creation_expression" => {
            let Some(initializer) = collect_kinds(expression, &["initializer_expression"])
                .into_iter()
                .next()
            else {
                return Vec::new();
            };
            let mut cursor = initializer.walk();
            initializer
                .children(&mut cursor)
                .filter(tree_sitter::Node::is_named)
                .collect()
        }
        "collection_expression" => collect_kinds(expression, &["collection_element"])
            .into_iter()
            .filter_map(first_named_child)
            .collect(),
        _ => Vec::new(),
    }
}

/// Whether an expression is fully compile-time literal: a scalar literal, a
/// negated numeric literal, or a non-empty array/collection literal whose
/// every element is itself compile-time literal. `null` does not count.
pub(crate) fn is_static_literal(expression: Node<'_>, source: &str) -> bool {
    let _ = source;
    match expression.kind() {
        "integer_literal" | "real_literal" | "string_literal" | "character_literal"
        | "boolean_literal" => true,
        "prefix_unary_expression" => first_named_child(expression)
            .is_some_and(|operand| matches!(operand.kind(), "integer_literal" | "real_literal")),
        "array_creation_expression"
        | "implicit_array_creation_expression"
        | "collection_expression" => {
            let elements = collection_element_expressions(expression);
            !elements.is_empty()
                && elements
                    .iter()
                    .all(|element| is_static_literal(*element, source))
        }
        _ => false,
    }
}

/// Bare type name → declared-type spelling for every local, parameter,
/// field, and property in the file. Later duplicates overwrite earlier ones;
/// cross-scope shadowing collapses to one entry, which this analyzer accepts
/// as part of its documented subset behavior.
pub(crate) fn declared_type_names<'a>(
    root: Node<'_>,
    source: &'a str,
) -> std::collections::HashMap<&'a str, &'a str> {
    let mut names = std::collections::HashMap::new();
    for declaration in collect_kinds(root, &["variable_declaration"]) {
        let Some(type_node) = declaration.child_by_field_name("type") else {
            continue;
        };
        let type_text = node_text(type_node, source);
        for declarator in collect_kinds(declaration, &["variable_declarator"]) {
            if let Some(name) = declarator.child_by_field_name("name") {
                names.insert(node_text(name, source), type_text);
            }
        }
    }
    for holder in collect_kinds(root, &["parameter", "property_declaration"]) {
        if let (Some(type_node), Some(name)) = (
            holder.child_by_field_name("type"),
            holder.child_by_field_name("name"),
        ) {
            names.insert(node_text(name, source), node_text(type_node, source));
        }
    }
    names
}

/// Whether a declared-type spelling names a non-nullable predefined value
/// type (numeric, `char`, `bool`); nullable spellings are rejected.
pub(crate) fn is_predefined_value_type_text(type_text: &str) -> bool {
    if type_text.contains('?') {
        return false;
    }
    let bare = simple_name(type_text);
    INTEGER_TYPES.contains(&bare)
        || FLOATING_TYPES.contains(&bare)
        || matches!(bare, "char" | "bool")
}

/// File-local class/struct/record/interface declarations, document order.
pub(crate) fn local_type_declarations(root: Node<'_>) -> Vec<Node<'_>> {
    collect_kinds(
        root,
        &[
            "class_declaration",
            "struct_declaration",
            "record_declaration",
            "interface_declaration",
        ],
    )
}

/// Field declarators (name identifier, declarator) declared directly by a type.
fn field_declarators(type_node: Node<'_>) -> Vec<(Node<'_>, Node<'_>)> {
    member_declarations_of_kind(type_node, "field_declaration")
        .into_iter()
        .flat_map(|field| collect_kinds(field, &["variable_declarator"]))
        .filter_map(|declarator| {
            declarator
                .child_by_field_name("name")
                .map(|name| (name, declarator))
        })
        .collect()
}

/// File-local named type declarations keyed by simple name.
pub(crate) fn local_type_table<'t>(
    root: Node<'t>,
    source: &'t str,
) -> std::collections::HashMap<&'t str, Node<'t>> {
    local_type_declarations(root)
        .into_iter()
        .filter_map(|declaration| {
            declaration
                .child_by_field_name("name")
                .map(|name| (node_text(name, source), declaration))
        })
        .collect()
}

/// Derived-field sites whose name collides (case-sensitively or not) with a
/// field of the type's first file-local base:
/// `(derived text, name, base-field text, base-type text)`.
pub(crate) fn shadowed_field_sites<'t>(
    root: Node<'t>,
    source: &'t str,
) -> Vec<(&'t str, Node<'t>, &'t str, &'t str)> {
    let types = local_type_table(root, source);
    let mut sites = Vec::new();
    for declaration in local_type_declarations(root) {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(base_name) = base_simple_names(declaration, source).first().copied() else {
            continue;
        };
        let Some(base_declaration) = types.get(base_name).copied() else {
            continue;
        };
        for (name_node, _) in field_declarators(declaration) {
            let derived = node_text(name_node, source);
            for base_field in field_declarators(base_declaration) {
                let base_field_text = node_text(base_field.0, source);
                if derived.eq_ignore_ascii_case(base_field_text) {
                    sites.push((derived, name_node, base_field_text, base_name));
                    break;
                }
            }
        }
    }
    sites
}

/// Override methods paired with their same-name method on the type's first
/// file-local base.
pub(crate) fn override_base_pairs<'t>(
    root: Node<'t>,
    source: &'t str,
) -> Vec<(Node<'t>, Node<'t>)> {
    matched_method_pairs(root, source, |modifiers| {
        has_modifier(modifiers, "override")
    })
}

/// Same-name method pairs across a type's first file-local base, selected by
/// a predicate over the derived method's modifiers.
pub(crate) fn matched_method_pairs<'t>(
    root: Node<'t>,
    source: &'t str,
    select: impl Fn(&[&str]) -> bool,
) -> Vec<(Node<'t>, Node<'t>)> {
    let types = local_type_table(root, source);
    let mut pairs = Vec::new();
    for declaration in local_type_declarations(root) {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(base_name) = base_simple_names(declaration, source).first().copied() else {
            continue;
        };
        let Some(base) = types.get(base_name).copied() else {
            continue;
        };
        let base_methods: std::collections::HashMap<&str, Node<'t>> =
            member_declarations_of_kind(base, "method_declaration")
                .into_iter()
                .filter_map(|method| {
                    method
                        .child_by_field_name("name")
                        .map(|name| (node_text(name, source), method))
                })
                .collect();
        for method in member_declarations_of_kind(declaration, "method_declaration") {
            if !select(&modifiers_of(method, source)) {
                continue;
            }
            if let Some(name) = method.child_by_field_name("name")
                && let Some(base_method) = base_methods.get(node_text(name, source))
            {
                pairs.push((method, *base_method));
            }
        }
    }
    pairs
}

/// A parameter's written default-value expression, when present. The default
/// is the trailing named child after the anonymous `=`; the parameter's type
/// and name also sit in the named-child run, so both are excluded.
pub(crate) fn parameter_default_value(parameter: Node<'_>) -> Option<Node<'_>> {
    let mut cursor = parameter.walk();
    let candidates: Vec<Node<'_>> = parameter
        .children(&mut cursor)
        .filter(tree_sitter::Node::is_named)
        .filter(|child| !matches!(child.kind(), "attribute_list" | "modifier"))
        .collect();
    let last = *candidates.last()?;
    (!parameter
        .child_by_field_name("name")
        .is_some_and(|name| name == last))
    .then_some(last)
}

/// Whether a proper `parameter` node carries the `params` modifier.
fn has_params_modifier(parameter: Node<'_>, source: &str) -> bool {
    let mut cursor = parameter.walk();
    parameter.children(&mut cursor).any(|child| {
        child.kind() == "params"
            || (child.kind() == "modifier" && node_text(child, source) == "params")
    })
}

/// One callable parameter, normalized over the grammar's two shapes: a proper
/// `parameter` node, or the flattened `params T name` spelling the grammar
/// emits bare inside the list (no `parameter` wrapper, never defaulted).
pub(crate) struct ParameterUnit<'a> {
    pub(crate) has_params: bool,
    pub(crate) default_value: Option<Node<'a>>,
    pub(crate) name: Option<Node<'a>>,
}

/// Normalized parameters of a callable's `parameter_list`, grouped across
/// the grammar's two shapes: proper `parameter` nodes, and the flattened
/// `params T name` spelling emitted bare inside the list.
pub(crate) fn parameter_units<'a>(declaration: Node<'a>, source: &str) -> Vec<ParameterUnit<'a>> {
    let Some(list) = declaration.child_by_field_name("parameters") else {
        return Vec::new();
    };
    let mut cursor = list.walk();
    let children: Vec<Node<'a>> = list.children(&mut cursor).collect();
    let mut groups: Vec<Vec<Node<'a>>> = vec![Vec::new()];
    for child in &children {
        if child.kind() == "," {
            groups.push(Vec::new());
        } else if let Some(group) = groups.last_mut() {
            group.push(*child);
        }
    }
    groups
        .into_iter()
        .filter(|group| group.iter().any(tree_sitter::Node::is_named))
        .map(|mut group| {
            let flattened_params = group.iter().any(|child| child.kind() == "params");
            group.retain(tree_sitter::Node::is_named);
            if !flattened_params
                && let [only] = group.as_slice()
                && only.kind() == "parameter"
            {
                return ParameterUnit {
                    has_params: has_params_modifier(*only, source),
                    default_value: parameter_default_value(*only),
                    name: only.child_by_field_name("name"),
                };
            }
            ParameterUnit {
                has_params: flattened_params,
                default_value: None,
                name: None,
            }
        })
        .collect()
}

/// File-local inheritance edges among classes/records/interfaces.
pub(crate) fn local_inheritance_graph<'a>(
    root: Node<'_>,
    source: &'a str,
) -> std::collections::HashMap<&'a str, Vec<&'a str>> {
    let mut graph: std::collections::HashMap<&'a str, Vec<&'a str>> =
        std::collections::HashMap::new();
    for declaration in local_type_declarations(root) {
        if is_error_tainted(declaration) {
            continue;
        }
        if let Some(name) = declaration.child_by_field_name("name") {
            graph
                .entry(node_text(name, source))
                .or_default()
                .extend(base_simple_names(declaration, source));
        }
    }
    graph
}

/// Seen-set BFS over an inheritance graph; `hits` decides the terminal node.
pub(crate) fn graph_reaches(
    graph: &std::collections::HashMap<&str, Vec<&str>>,
    start: &str,
    hits: impl Fn(&str) -> bool,
) -> bool {
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut queue: Vec<&str> = graph.get(start).cloned().unwrap_or_default();
    while let Some(current) = queue.pop() {
        if hits(current) {
            return true;
        }
        if seen.insert(current)
            && let Some(successors) = graph.get(current)
        {
            queue.extend(successors.iter().copied());
        }
    }
    false
}
