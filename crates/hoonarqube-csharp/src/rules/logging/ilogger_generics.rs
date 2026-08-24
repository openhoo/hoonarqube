use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{enclosing_type, first_named_child};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6672 — an `ILogger<T>` belongs to the type that logs.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node) {
            continue;
        }
        let Some(name) = type_node.child_by_field_name("name") else {
            continue;
        };
        let type_name = node_text(name, source);
        for declaration in collect_kinds(type_node, &["variable_declaration"]) {
            if enclosing_type(declaration).is_none_or(|owner| owner.id() != type_node.id()) {
                continue;
            }
            let Some(type_child) = first_named_child(declaration) else {
                continue;
            };
            let Some(inner) = node_text(type_child, source)
                .strip_prefix("ILogger<")
                .and_then(|rest| rest.strip_suffix('>'))
            else {
                continue;
            };
            if simple_name(inner) != type_name {
                issues.push(issue(
                    language,
                    "S6672",
                    format!("Use 'ILogger<{type_name}>' for loggers of this type."),
                    range_of(declaration),
                ));
            }
        }
    }
    issues
}
