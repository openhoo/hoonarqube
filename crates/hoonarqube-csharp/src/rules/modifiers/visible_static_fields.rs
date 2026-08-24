use super::support::has_any_accessibility;
use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2223 — visible non-constant static fields hide shared
/// mutable state; `readonly` does not rescue them.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        if has_modifier(&modifiers, "static")
            && !has_modifier(&modifiers, "const")
            && has_any_accessibility(&modifiers)
        {
            issues.push(issue(
                language,
                "S2223",
                "Make this static field private.",
                range_of(field),
            ));
        }
    }
    issues
}
