use super::support::enclosing_method;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::base_call_name;
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3397 — calling `base.Equals` from within an `Equals` override
/// recurses into object identity semantics.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if is_error_tainted(invocation) || base_call_name(invocation, source) != Some("Equals") {
            continue;
        }
        let in_equals_override = enclosing_method(invocation).is_some_and(|method| {
            method
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == "Equals")
                && has_modifier(&modifiers_of(method, source), "override")
        });
        if in_equals_override {
            issues.push(issue(
                language,
                "S3397",
                "Remove this 'base.Equals' call from the 'Equals' override.",
                range_of(invocation),
            ));
        }
    }
    issues
}
