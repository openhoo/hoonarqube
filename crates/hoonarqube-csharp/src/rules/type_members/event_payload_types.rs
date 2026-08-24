use super::support::is_event_args_parameter;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, parameters_of, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4220 — events whose custom delegate payload is not an
/// EventArgs-derived type lose the framework's sender/payload conventions.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let custom_delegates: std::collections::HashMap<&str, bool> =
        collect_kinds(root, &["delegate_declaration"])
            .into_iter()
            .filter_map(|delegate| {
                let name = delegate.child_by_field_name("name")?;
                let parameters = parameters_of(delegate);
                let carries_args = parameters
                    .last()
                    .is_some_and(|parameter| is_event_args_parameter(*parameter, source));
                Some((node_text(name, source), carries_args))
            })
            .collect();
    if custom_delegates.is_empty() {
        return Vec::new();
    }
    collect_kinds(root, &["event_field_declaration"])
        .into_iter()
        .flat_map(|event_field| collect_kinds(event_field, &["variable_declaration"]))
        .filter(|declaration| {
            declaration
                .child_by_field_name("type")
                .and_then(|type_node| {
                    custom_delegates.get(simple_name(node_text(type_node, source)))
                })
                .copied()
                .is_some_and(|carries_args| !carries_args)
        })
        .filter(|declaration| {
            declaration
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    custom_delegates.contains_key(simple_name(node_text(type_node, source)))
                })
        })
        .flat_map(|declaration| collect_kinds(declaration, &["variable_declarator"]))
        .filter_map(|declarator| declarator.child_by_field_name("name"))
        .map(|name_node| {
            issue(
                language,
                "S4220",
                format!(
                    "Have the event '{}' carry an 'EventArgs'-derived payload.",
                    node_text(name_node, source)
                ),
                range_of(name_node),
            )
        })
        .collect()
}
