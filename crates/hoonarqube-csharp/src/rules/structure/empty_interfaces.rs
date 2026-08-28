use super::support::name_anchor;
use super::support::type_has_no_members;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, range_of};
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4023 — interfaces carry members.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for interface in collect_kinds(root, &["interface_declaration"]) {
        if is_error_tainted(interface) || has_modifier(&modifiers_of(interface, source), "partial")
        {
            continue;
        }
        if type_has_no_members(interface) {
            issues.push(issue(
                language,
                "S4023",
                "Remove this interface or add members to it.",
                range_of(name_anchor(interface), source),
            ));
        }
    }
    issues
}
