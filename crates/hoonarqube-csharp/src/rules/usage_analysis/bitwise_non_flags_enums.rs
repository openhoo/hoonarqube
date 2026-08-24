use super::support::typed_variables;
use crate::CsLanguage;
use crate::cst::{
    attributes_of, collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name,
};
use crate::rules::modifiers::has_attribute;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3265 — bitwise operations need `[Flags]` enums.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let (enum_types, enum_members) = non_flags_enum_names(root, source);
    if enum_types.is_empty() {
        return Vec::new();
    }
    let mut value_names = enum_members;
    for (variable, type_name) in typed_variables(root, source) {
        if enum_types.contains(type_name) {
            value_names.insert(variable);
        }
    }
    for parameter in collect_kinds(root, &["parameter"]) {
        let Some(type_node) = parameter.child_by_field_name("type") else {
            continue;
        };
        if !enum_types.contains(simple_name(node_text(type_node, source))) {
            continue;
        }
        let Some(name) = parameter.child_by_field_name("name") else {
            continue;
        };
        value_names.insert(node_text(name, source));
    }
    let mut issues = Vec::new();
    let mut expressions = collect_kinds(root, &["binary_expression"]);
    expressions.extend(collect_kinds(root, &["assignment_expression"]));
    for expression in expressions {
        if is_error_tainted(expression) || bitwise_operator(expression).is_none() {
            continue;
        }
        let touches_enum = collect_kinds(expression, &["identifier"])
            .iter()
            .any(|identifier| value_names.contains(node_text(*identifier, source)));
        if touches_enum {
            issues.push(issue(
                language,
                "S3265",
                "This enum is not marked [Flags]; avoid bitwise operations on its values.",
                range_of(expression),
            ));
        }
    }
    issues
}

/// Non-`[Flags]` enum type names declared in the file plus the names of
/// their members.
fn non_flags_enum_names<'a>(
    root: Node<'a>,
    source: &'a str,
) -> (
    std::collections::HashSet<&'a str>,
    std::collections::HashSet<&'a str>,
) {
    let mut types = std::collections::HashSet::new();
    let mut members = std::collections::HashSet::new();
    for enum_node in collect_kinds(root, &["enum_declaration"]) {
        if has_attribute(&attributes_of(enum_node, source), "Flags") {
            continue;
        }
        if let Some(name) = enum_node.child_by_field_name("name") {
            types.insert(node_text(name, source));
        }
        for body_child in collect_kinds(enum_node, &["enum_member_declaration"]) {
            if let Some(name) = body_child.child_by_field_name("name") {
                members.insert(node_text(name, source));
            }
        }
    }
    (types, members)
}

/// The bitwise operator of a binary or assignment expression.
fn bitwise_operator(expression: Node<'_>) -> Option<&'static str> {
    const OPERATORS: [&str; 6] = ["|", "&", "^", "|=", "&=", "^="];
    let mut cursor = expression.walk();
    let kind = expression
        .children(&mut cursor)
        .find(|child| !child.is_named())?
        .kind();
    OPERATORS
        .iter()
        .find(|operator| **operator == kind)
        .copied()
}
