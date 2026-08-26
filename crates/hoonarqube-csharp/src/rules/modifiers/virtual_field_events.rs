use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2290 — virtual field-like events cannot be overridden in any
/// meaningful way.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for event_field in collect_kinds(root, &["event_field_declaration"]) {
        if has_modifier(&modifiers_of(event_field, source), "virtual") {
            issues.push(issue(
                language,
                "S2290",
                "Remove the 'virtual' modifier from this event.",
                range_of(event_field, source),
            ));
        }
    }
    issues
}
