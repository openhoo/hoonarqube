use super::support::is_event_handler_shape;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3906 — delegates shaped like event handlers must return void:
/// raising an event should not hand callers a result to ignore.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["delegate_declaration"])
        .into_iter()
        .filter(|delegate| {
            is_event_handler_shape(*delegate, source)
                && delegate
                    .child_by_field_name("type")
                    .is_some_and(|returns| node_text(returns, source) != "void")
        })
        .filter_map(|delegate| delegate.child_by_field_name("name"))
        .map(|name_node| {
            issue(
                language,
                "S3906",
                "Change the return type of this delegate to 'void'.".to_string(),
                range_of(name_node, source),
            )
        })
        .collect()
}
