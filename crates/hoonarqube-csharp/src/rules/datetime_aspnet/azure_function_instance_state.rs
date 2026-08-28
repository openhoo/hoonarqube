use super::support::azure_function_methods;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::expressions::{expression_name, first_named_child};
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6419 — Azure Function invocations must not mutate static
/// state shared by concurrent executions.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut static_fields = std::collections::HashSet::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        for field in member_declarations_of_kind(type_node, "field_declaration") {
            let modifiers = modifiers_of(field, source);
            if !has_modifier(&modifiers, "static")
                || has_modifier(&modifiers, "readonly")
                || has_modifier(&modifiers, "const")
            {
                continue;
            }
            for declarator in collect_kinds(field, &["variable_declarator"]) {
                if let Some(name) = declarator.child_by_field_name("name") {
                    static_fields.insert(node_text(name, source));
                }
            }
        }
    }
    let mut issues = Vec::new();
    for method in azure_function_methods(root, source) {
        for assignment in collect_kinds(method, &["assignment_expression"]) {
            if let Some(target) = assignment.child_by_field_name("left")
                && expression_name(target, source).is_some_and(|name| static_fields.contains(name))
            {
                issues.push(static_state_issue(target, source, language));
            }
        }
        for unary in collect_kinds(
            method,
            &["prefix_unary_expression", "postfix_unary_expression"],
        ) {
            if is_error_tainted(unary) {
                continue;
            }
            if let Some(target) = first_named_child(unary)
                && expression_name(target, source).is_some_and(|name| static_fields.contains(name))
            {
                issues.push(static_state_issue(target, source, language));
            }
        }
    }
    issues
}

fn static_state_issue(target: Node<'_>, source: &str, language: CsLanguage) -> Issue {
    issue(
        language,
        "S6419",
        "Do not modify a static state from Azure Function.",
        range_of(target, source),
    )
}
