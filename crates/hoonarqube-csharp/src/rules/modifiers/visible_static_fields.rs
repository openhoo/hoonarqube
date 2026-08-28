use super::support::has_any_accessibility;
use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
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
            && !has_modifier(&modifiers, "readonly")
            && has_any_accessibility(&modifiers)
        {
            for declarator in collect_kinds(field, &["variable_declarator"]) {
                let name = declarator.child_by_field_name("name").unwrap_or(declarator);
                let name_text = node_text(name, source);
                issues.push(issue(
                    language,
                    "S2223",
                    format!(
                        "Change the visibility of '{name_text}' or make it 'const' or 'readonly'."
                    ),
                    range_of(name, source),
                ));
            }
        }
    }
    issues
}
