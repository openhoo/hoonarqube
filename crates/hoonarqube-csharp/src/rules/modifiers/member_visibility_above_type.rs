use super::support::accessibility_rank;
use super::support::has_any_accessibility;
use super::support::type_declared_rank;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3059 — members cannot be more visible than their container;
/// undeclared members default to private and never exceed it.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const MEMBER_KINDS: [&str; 14] = [
        "class_declaration",
        "struct_declaration",
        "record_declaration",
        "enum_declaration",
        "interface_declaration",
        "delegate_declaration",
        "method_declaration",
        "property_declaration",
        "event_declaration",
        "event_field_declaration",
        "field_declaration",
        "indexer_declaration",
        "operator_declaration",
        "constructor_declaration",
    ];
    let mut issues = Vec::new();
    for type_node in collect_kinds(
        root,
        &[
            "class_declaration",
            "struct_declaration",
            "record_declaration",
        ],
    ) {
        let type_rank = type_declared_rank(type_node, source);
        for member in type_members(type_node) {
            if !MEMBER_KINDS.contains(&member.kind()) {
                continue;
            }
            let member_modifiers = modifiers_of(member, source);
            if !has_any_accessibility(&member_modifiers)
                || accessibility_rank(&member_modifiers) <= type_rank
            {
                continue;
            }
            issues.push(issue(
                language,
                "S3059",
                "Reduce this member's visibility to match its container.",
                range_of(member, source),
            ));
        }
    }
    issues
}
