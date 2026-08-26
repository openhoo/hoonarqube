use super::support::static_field_declarators;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::modifiers::type_parameter_list_of;
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
            let Some(name_node) = declarator.child_by_field_name("name") else {
                continue;
            };
            issues.push(issue(
                language,
                "S2743",
                format!(
                    "Move the static field '{}' to a non-generic type; it is shared across instantiations.",
                    node_text(name_node, source)
                ),
                range_of(name_node, source),
            ));
        }
    }
    issues
}
