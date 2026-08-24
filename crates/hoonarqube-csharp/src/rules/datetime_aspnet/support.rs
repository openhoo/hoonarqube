use crate::cst::{collect_kinds, is_error_tainted, modifiers_of, node_text};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::literals::{argument_expression, string_literals};
use crate::rules::modifiers::{has_any_attribute, has_modifier};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::security::call_argument_nodes;
use tree_sitter::Node;

/// The `argument` expressions of a `new T(...)` creation.
pub(crate) fn creation_argument_expressions(creation: Node<'_>) -> Vec<Node<'_>> {
    call_argument_nodes(creation)
        .iter()
        .copied()
        .map(argument_expression)
        .collect()
}

/// Methods attributed `[Function]` or `[FunctionName]` (Azure Functions).
pub(crate) fn azure_function_methods<'t>(root: Node<'t>, source: &str) -> Vec<Node<'t>> {
    collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|method| !is_error_tainted(*method))
        .filter(|method| has_any_attribute(*method, source, &["Function", "FunctionName"]))
        .collect()
}

/// Types hosting at least one Azure Function method.
pub(crate) fn azure_function_classes<'t>(root: Node<'t>, source: &str) -> Vec<Node<'t>> {
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter(|type_node| {
            member_declarations_of_kind(*type_node, "method_declaration")
                .iter()
                .any(|method| has_any_attribute(*method, source, &["Function", "FunctionName"]))
        })
        .collect()
}

/// Attribute names carrying route templates.
pub(crate) const ROUTE_ATTRIBUTE_NAMES: [&str; 6] = [
    "Route",
    "HttpGet",
    "HttpPost",
    "HttpPut",
    "HttpDelete",
    "HttpPatch",
];

/// Route-template string literals of an attribute application's arguments.
pub(crate) fn route_template_literals(args: Option<Node<'_>>) -> Vec<Node<'_>> {
    args.map(string_literals).unwrap_or_default()
}

/// Whether an attribute application carries a route template.
pub(crate) fn is_route_attribute(name: &str) -> bool {
    ROUTE_ATTRIBUTE_NAMES.contains(&name.trim_end_matches("Attribute"))
}

/// HTTP verb attribute names marking ASP.NET actions.
pub(crate) const VERB_ATTRIBUTE_NAMES: [&str; 6] = [
    "HttpGet",
    "HttpPost",
    "HttpPut",
    "HttpDelete",
    "HttpPatch",
    "AcceptVerbs",
];

/// Whether any attribute on the type marks it API-controller-like.
pub(crate) fn is_api_controller_like(type_node: Node<'_>, source: &str) -> bool {
    has_any_attribute(type_node, source, &["ApiController"])
        || type_node
            .child_by_field_name("name")
            .is_some_and(|name| node_text(name, source).ends_with("Controller"))
}

/// Public action candidates declared by a controller-like type.
pub(crate) fn controller_actions<'t>(type_node: Node<'t>, source: &str) -> Vec<Node<'t>> {
    member_declarations_of_kind(type_node, "method_declaration")
        .into_iter()
        .filter(|method| {
            let modifiers = modifiers_of(*method, source);
            has_modifier(&modifiers, "public")
                && !has_modifier(&modifiers, "static")
                && !has_modifier(&modifiers, "override")
        })
        .filter(|method| {
            method
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) != "Dispose")
        })
        .filter(|method| !has_any_attribute(*method, source, &["NonAction"]))
        .collect()
}
