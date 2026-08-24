use super::support::name_is_guarded;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, parameters_of, range_of};
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3655 — reading `.Value` of a nullable without checking
/// `HasValue` throws when the value is absent. Bound: nullable-typed
/// parameters and locals of the enclosing callable; any member-wide
/// guard (`HasValue`, null comparison, `is not null`, `?.`) exempts the
/// name.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declaration in callable_declarations(root) {
        let Some(body) = body_of(declaration) else {
            continue;
        };
        let mut nullable_names = std::collections::HashSet::new();
        for parameter in parameters_of(declaration) {
            if parameter_ends_nullable(parameter, source)
                && let Some(name) = parameter.child_by_field_name("name")
            {
                nullable_names.insert(node_text(name, source).to_owned());
            }
        }
        for variable in collect_kinds(body, &["variable_declaration"]) {
            let nullable = variable
                .child_by_field_name("type")
                .is_some_and(|type_node| node_text(type_node, source).ends_with('?'));
            if !nullable {
                continue;
            }
            for declarator in collect_kinds(variable, &["variable_declarator"]) {
                if let Some(name) = declarator.child_by_field_name("name") {
                    nullable_names.insert(node_text(name, source).to_owned());
                }
            }
        }
        if nullable_names.is_empty() {
            continue;
        }
        let body_text = node_text(body, source);
        for access in collect_kinds(body, &["member_access_expression"]) {
            let Some(member) = access.child_by_field_name("name") else {
                continue;
            };
            if node_text(member, source) != "Value" {
                continue;
            }
            let Some(base) = access.child_by_field_name("expression") else {
                continue;
            };
            if base.kind() != "identifier" {
                continue;
            }
            let name = node_text(base, source);
            if nullable_names.contains(name) && !name_is_guarded(body_text, name) {
                issues.push(issue(
                    language,
                    "S3655",
                    format!("Check 'HasValue' before accessing '{name}.Value'."),
                    range_of(access),
                ));
            }
        }
    }
    issues
}

/// Callables whose parameters and locals the nullable checks consider.
const CALLABLE_DECLARATION_KINDS: [&str; 7] = [
    "method_declaration",
    "constructor_declaration",
    "destructor_declaration",
    "operator_declaration",
    "accessor_declaration",
    "local_function_statement",
    "property_declaration",
];

fn callable_declarations(root: Node<'_>) -> Vec<Node<'_>> {
    collect_kinds(root, &CALLABLE_DECLARATION_KINDS)
}

fn parameter_ends_nullable(parameter: Node<'_>, source: &str) -> bool {
    parameter
        .child_by_field_name("type")
        .is_some_and(|type_node| node_text(type_node, source).ends_with('?'))
}
