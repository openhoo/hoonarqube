use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, parameters_of, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3906 — delegates shaped like event handlers must return void:
/// raising an event should not hand callers a result to ignore.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let invalid_delegates: std::collections::HashSet<&str> =
        collect_kinds(root, &["delegate_declaration"])
            .into_iter()
            .filter(|delegate| {
                let parameters = parameters_of(*delegate);
                let returns_void = delegate
                    .child_by_field_name("type")
                    .is_some_and(|returns| node_text(returns, source) == "void");
                let sender = parameters.first().is_some_and(|parameter| {
                    parameter
                        .child_by_field_name("type")
                        .is_some_and(|ty| simple_name(node_text(ty, source)) == "object")
                        && parameter
                            .child_by_field_name("name")
                            .is_some_and(|name| node_text(name, source) == "sender")
                });
                let args = parameters.get(1).is_some_and(|parameter| {
                    parameter
                        .child_by_field_name("type")
                        .is_some_and(|ty| simple_name(node_text(ty, source)).ends_with("EventArgs"))
                        && parameter
                            .child_by_field_name("name")
                            .is_some_and(|name| node_text(name, source) == "e")
                });
                !returns_void || parameters.len() != 2 || !sender || !args
            })
            .filter_map(|delegate| delegate.child_by_field_name("name"))
            .map(|name| node_text(name, source))
            .collect();
    collect_kinds(root, &["event_field_declaration"])
        .into_iter()
        .flat_map(|event_field| collect_kinds(event_field, &["variable_declaration"]))
        .filter(|declaration| {
            declaration
                .child_by_field_name("type")
                .is_some_and(|ty| invalid_delegates.contains(simple_name(node_text(ty, source))))
        })
        .filter_map(|declaration| declaration.child_by_field_name("type"))
        .map(|event_type| {
            issue(
                language,
                "S3906",
                "Change the signature of that event handler to match the specified signature.",
                range_of(event_type, source),
            )
        })
        .collect()
}
