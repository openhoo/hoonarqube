use crate::cst::{collect_kinds, is_error_tainted, node_text};
use crate::rules::expressions::{
    callee_name, enclosing_type, invocation_arguments, invocation_targets,
};
use crate::rules::literals::{argument_expression, is_string_literal, literal_inner_text};
use tree_sitter::Node;

/// Whether an invocation feeds a composite format template (`string.Format`,
/// `AppendFormat`, `Console.Write(Line)`).
pub(crate) fn is_composite_format_call(invocation: Node<'_>, source: &str) -> bool {
    invocation_targets(invocation, source, Some("string"), &["Format"])
        || invocation_targets(invocation, source, Some("String"), &["Format"])
        || callee_name(invocation, source) == Some("AppendFormat")
        || invocation_targets(invocation, source, Some("Console"), &["Write", "WriteLine"])
}

/// The composite-format template of a call with the number of arguments
/// following it; tolerates a leading `IFormatProvider` argument.
pub(crate) fn composite_template<'a>(
    call: Node<'a>,
    source: &'a str,
) -> Option<(Node<'a>, &'a str, usize)> {
    let arguments = invocation_arguments(call);
    let position = arguments
        .iter()
        .position(|argument| is_string_literal(argument_expression(*argument)))?;
    let literal = argument_expression(arguments[position]);
    let budget = arguments.len() - position - 1;
    Some((literal, literal_inner_text(literal, source), budget))
}

/// The operator token behind a `left/right` expression's dedicated field.
pub(crate) fn child_operator<'a>(expression: Node<'_>, source: &'a str) -> Option<&'a str> {
    expression
        .child_by_field_name("operator")
        .map(|operator| node_text(operator, source))
}

/// Methods grouped by declared name within each type.
pub(crate) fn methods_grouped_by_name<'t>(
    root: Node<'t>,
    source: &str,
) -> std::collections::BTreeMap<(usize, String), Vec<Node<'t>>> {
    let mut groups: std::collections::BTreeMap<(usize, String), Vec<Node<'t>>> =
        std::collections::BTreeMap::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        let owner = enclosing_type(method).map_or(0, |owner| owner.id());
        let name = method
            .child_by_field_name("name")
            .map(|name| node_text(name, source).to_string())
            .unwrap_or_default();
        groups.entry((owner, name)).or_default().push(method);
    }
    groups
}

/// The leading token of a node (`base` of a `base.M` member access).
pub(crate) fn first_child_token_text<'a>(node: Node<'_>, source: &'a str) -> &'a str {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .next()
        .map_or("", |first| node_text(first, source))
}
