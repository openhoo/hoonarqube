use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, parameters_of, simple_name};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// Static, non-constant field declarators declared directly by a type.
pub(crate) fn static_field_declarators<'t>(type_node: Node<'t>, source: &'t str) -> Vec<Node<'t>> {
    member_declarations_of_kind(type_node, "field_declaration")
        .into_iter()
        .filter(|field| {
            let mods = modifiers_of(*field, source);
            has_modifier(&mods, "static") && !has_modifier(&mods, "const")
        })
        .flat_map(|field| collect_kinds(field, &["variable_declarator"]))
        .collect()
}

/// Names assigned on the left of assignments inside `scope`.
pub(crate) fn assigned_names<'a>(scope: Node<'_>, source: &'a str) -> Vec<&'a str> {
    collect_kinds(scope, &["assignment_expression"])
        .into_iter()
        .filter_map(|assignment| {
            assignment
                .child_by_field_name("left")
                .filter(|left| left.kind() == "identifier")
                .map(|left| node_text(left, source))
        })
        .collect()
}

/// csharpsquid:S3962 — literal-initialized `static readonly` fields should be
/// `const`: their values never change at runtime.
pub(crate) fn is_literal_node(node: Node<'_>) -> bool {
    matches!(
        node.kind(),
        "string_literal"
            | "verbatim_string_literal"
            | "integer_literal"
            | "real_literal"
            | "boolean_literal"
            | "character_literal"
    )
}

/// Whether a parameter type names an EventArgs-derived type.
pub(crate) fn is_event_args_parameter(parameter: Node<'_>, source: &str) -> bool {
    parameter
        .child_by_field_name("type")
        .is_some_and(|type_node| simple_name(node_text(type_node, source)).ends_with("EventArgs"))
}

/// Signature shape `(object sender, TEventArgs e)`.
pub(crate) fn is_event_handler_shape(delegate: Node<'_>, source: &str) -> bool {
    let parameters = parameters_of(delegate);
    parameters.len() == 2
        && parameters[0]
            .child_by_field_name("type")
            .is_some_and(|type_node| simple_name(node_text(type_node, source)) == "object")
        && is_event_args_parameter(parameters[1], source)
}

/// Whether any assembly-level (`[assembly: ...]`) attribute is present.
pub(crate) fn assembly_attribute_names<'a>(root: Node<'_>, source: &'a str) -> Vec<&'a str> {
    collect_kinds(root, &["global_attribute"])
        .iter()
        .filter(|global| {
            global
                .child(1)
                .is_some_and(|target| node_text(target, source) == "assembly")
        })
        .flat_map(|global| collect_kinds(*global, &["attribute"]))
        .filter_map(|attribute| attribute.child_by_field_name("name"))
        .map(|name| simple_name(node_text(name, source)))
        .collect()
}

/// File-level finding anchored at the top of the file, like S1451.
pub(crate) fn file_level_issue(language: CsLanguage, rule: &str, message: &str) -> Issue {
    issue(
        language,
        rule,
        message,
        hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line: 1, column: 0 },
            end: hoonarqube_ir::Pos { line: 1, column: 0 },
        },
    )
}

/// Members of a flags enumeration with their explicit value nodes.
pub(crate) fn enum_members(enum_node: Node<'_>) -> Vec<(Node<'_>, Option<Node<'_>>)> {
    collect_kinds(enum_node, &["enum_member_declaration"])
        .into_iter()
        .map(|member| (member, member.child_by_field_name("value")))
        .collect()
}
