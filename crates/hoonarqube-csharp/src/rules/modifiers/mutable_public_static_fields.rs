use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2386 — public static mutable fields invite races; only
/// `readonly` (or a property) settles them down.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        if has_modifier(&modifiers, "public")
            && has_modifier(&modifiers, "static")
            && !has_modifier(&modifiers, "readonly")
            && !has_modifier(&modifiers, "const")
        {
            issues.push(issue(
                language,
                "S2386",
                "Make this field readonly or replace it with a property.",
                range_of(field, source),
            ));
        }
    }
    issues
}
