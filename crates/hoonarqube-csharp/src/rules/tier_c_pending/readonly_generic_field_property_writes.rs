use super::support::member_declared_type;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::{expression_name, first_named_child};
use crate::rules::logging::field_declarator_names;
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::type_members;
use crate::rules::usage_analysis::unconstrained_generic_parameters;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2934 — property writes through `readonly` fields typed by an
/// unconstrained generic parameter. Subset: assignment expressions whose
/// left side is a property of such a field, inside the declaring type;
/// `class`/`struct`/`notnull`-constrained parameters and non-generic
/// readonly fields stay clean.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declaration in collect_kinds(
        root,
        &[
            "class_declaration",
            "struct_declaration",
            "record_declaration",
        ],
    ) {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(unconstrained) = unconstrained_generic_parameters(declaration, source) else {
            continue;
        };
        let readonly_fields: std::collections::HashSet<&str> = type_members(declaration)
            .into_iter()
            .filter(|member| {
                member.kind() == "field_declaration"
                    && has_modifier(&modifiers_of(*member, source), "readonly")
            })
            .filter(|member| {
                member_declared_type(*member)
                    .is_some_and(|type_node| unconstrained.contains(node_text(type_node, source)))
            })
            .flat_map(|member| field_declarator_names(member, source))
            .collect();
        if readonly_fields.is_empty() {
            continue;
        }
        for assignment in collect_kinds(declaration, &["assignment_expression"]) {
            if is_error_tainted(assignment) {
                continue;
            }
            let Some(left) = first_named_child(assignment) else {
                continue;
            };
            if left.kind() != "member_access_expression" {
                continue;
            }
            let Some(object) = first_named_child(left) else {
                continue;
            };
            let written = match object.kind() {
                "identifier" => Some(node_text(object, source)),
                "member_access_expression" => expression_name(object, source),
                _ => None,
            };
            if written.is_some_and(|name| readonly_fields.contains(name)) {
                issues.push(issue(
                    language,
                    "S2934",
                    "This property write may mutate a copy; constrain the type parameter to reference types or drop the 'readonly' modifier.",
                    range_of(assignment),
                ));
            }
        }
    }
    issues
}
