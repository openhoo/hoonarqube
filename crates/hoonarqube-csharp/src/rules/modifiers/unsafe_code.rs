use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6640 — unsafe blocks and unsafe declarations opt out of
/// memory-safety guarantees.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const UNSAFE_DECLARATION_KINDS: [&str; 11] = [
        "class_declaration",
        "struct_declaration",
        "record_declaration",
        "interface_declaration",
        "delegate_declaration",
        "field_declaration",
        "event_field_declaration",
        "method_declaration",
        "property_declaration",
        "indexer_declaration",
        "operator_declaration",
    ];
    let mut issues = Vec::new();
    for statement in collect_kinds(root, &["unsafe_statement"]) {
        issues.push(issue(
            language,
            "S6640",
            "Remove this unsafe block.",
            range_of(statement),
        ));
    }
    for declaration in collect_kinds(root, &UNSAFE_DECLARATION_KINDS) {
        if !has_modifier(&modifiers_of(declaration, source), "unsafe") {
            continue;
        }
        let anchor = declaration
            .child_by_field_name("name")
            .unwrap_or(declaration);
        issues.push(issue(
            language,
            "S6640",
            "Remove the 'unsafe' modifier from this declaration.",
            range_of(anchor),
        ));
    }
    issues
}
