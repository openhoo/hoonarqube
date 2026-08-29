use super::support::{field_declarators, field_type, has_modifier};
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4000 — externally visible unmanaged pointer fields must be
/// private or protected-readonly.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        if !(has_modifier(&modifiers, "public") || has_modifier(&modifiers, "protected"))
            || has_modifier(&modifiers, "readonly")
        {
            continue;
        }
        let Some(field_type) = field_type(field) else {
            continue;
        };
        if field_type.kind() != "pointer_type"
            && !matches!(
                simple_name(node_text(field_type, source)),
                "IntPtr" | "UIntPtr" | "HandleRef"
            )
        {
            continue;
        }
        for declarator in field_declarators(field) {
            let Some(name) = declarator.child_by_field_name("name") else {
                continue;
            };
            issues.push(issue(
                language,
                "S4000",
                format!(
                    "Make '{}' 'private' or 'protected readonly'.",
                    node_text(name, source)
                ),
                range_of(name, source),
            ));
        }
    }
    issues
}
