use super::support::static_field_declarators;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use crate::rules::modifiers::{has_modifier, type_parameter_list_of};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2743 — static fields of generic types are shared by every
/// instantiation, which is almost never intended.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if type_parameter_list_of(type_node).is_none() {
            continue;
        }
        for declarator in static_field_declarators(type_node, source) {
            let Some(field) = declarator
                .parent()
                .and_then(|declaration| declaration.parent())
            else {
                continue;
            };
            if has_modifier(&modifiers_of(field, source), "readonly") {
                continue;
            }
            let Some(name_node) = declarator.child_by_field_name("name") else {
                continue;
            };
            issues.push(issue(
                language,
                "S2743",
                "A static field in a generic type is not shared among instances of different close constructed types.",
                range_of(name_node, source),
            ));
        }
    }
    issues
}
