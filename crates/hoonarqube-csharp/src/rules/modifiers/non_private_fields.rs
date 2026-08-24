use super::support::accessibility_rank;
use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2357 — fields should be private; constants are S2339's
/// territory.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        if !has_modifier(&modifiers, "const") && accessibility_rank(&modifiers) > 1 {
            issues.push(issue(
                language,
                "S2357",
                "Make this field private.",
                range_of(field),
            ));
        }
    }
    issues
}
