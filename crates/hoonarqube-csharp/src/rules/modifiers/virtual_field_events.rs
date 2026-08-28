use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2290 — virtual field-like events cannot be overridden in any
/// meaningful way.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for event_field in collect_kinds(root, &["event_field_declaration"]) {
        if has_modifier(&modifiers_of(event_field, source), "virtual") {
            let virtual_keyword = collect_kinds(event_field, &["virtual"])
                .into_iter()
                .next()
                .unwrap_or(event_field);
            let name = collect_kinds(event_field, &["variable_declarator"])
                .into_iter()
                .next()
                .and_then(|declarator| declarator.child_by_field_name("name"))
                .map_or("event", |name| node_text(name, source));
            issues.push(issue(
                language,
                "S2290",
                format!("Remove this 'virtual' modifier of '{name}'."),
                range_of(virtual_keyword, source),
            ));
        }
    }
    issues
}
