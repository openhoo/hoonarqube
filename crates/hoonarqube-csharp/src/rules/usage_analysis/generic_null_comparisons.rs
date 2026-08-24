use super::support::unconstrained_generic_parameters;
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, node_text, range_of, signature_regions, simple_name,
};
use crate::rules::expressions::{comparisons, operator_of};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2955 — unconstrained generic values mislead `null` checks.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let values = unconstrained_generic_value_names(root, source);
    let mut issues = Vec::new();
    for (expression, left, right) in comparisons(root) {
        if !matches!(operator_of(expression), Some("==" | "!=")) {
            continue;
        }
        for operand in [left, right] {
            if operand.kind() != "identifier"
                || !values.contains(node_text(operand, source))
                || [left, right]
                    .iter()
                    .all(|side| (*side).kind() != "null_literal")
            {
                continue;
            }
            issues.push(issue(
                language,
                "S2955",
                format!(
                    "Constrain '{}' or avoid comparing it with null.",
                    node_text(operand, source)
                ),
                range_of(expression),
            ));
        }
    }
    issues
}

/// Names of parameters and locals typed by an unconstrained generic
/// parameter of their enclosing declaration.
fn unconstrained_generic_value_names(
    root: Node<'_>,
    source: &str,
) -> std::collections::HashSet<String> {
    let mut declarations = collect_kinds(root, &TYPE_DECLARATION_KINDS);
    declarations.extend(collect_kinds(root, &["method_declaration"]));
    let mut values = std::collections::HashSet::new();
    for declaration in declarations {
        if is_error_tainted(declaration) {
            continue;
        }
        let Some(generic_names) = unconstrained_generic_parameters(declaration, source) else {
            continue;
        };
        for region in signature_regions(declaration) {
            for parameter in collect_kinds(region, &["parameter"]) {
                let Some(type_node) = parameter.child_by_field_name("type") else {
                    continue;
                };
                if !generic_names.contains(simple_name(node_text(type_node, source))) {
                    continue;
                }
                let Some(name) = parameter.child_by_field_name("name") else {
                    continue;
                };
                values.insert(node_text(name, source).to_string());
            }
        }
        for variable_declaration in collect_kinds(declaration, &["variable_declaration"]) {
            let Some(type_node) = variable_declaration.child_by_field_name("type") else {
                continue;
            };
            if !generic_names.contains(simple_name(node_text(type_node, source))) {
                continue;
            }
            for declarator in collect_kinds(variable_declaration, &["variable_declarator"]) {
                if let Some(name) = declarator.child_by_field_name("name") {
                    values.insert(node_text(name, source).to_string());
                }
            }
        }
    }
    values
}
