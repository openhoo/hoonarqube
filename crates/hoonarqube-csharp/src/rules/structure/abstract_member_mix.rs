use super::support::name_anchor;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, range_of};
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1694 — abstract classes mix abstract with concrete members.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_declaration)
            || !has_modifier(&modifiers_of(class_declaration, source), "abstract")
        {
            continue;
        }
        let mut abstract_members = 0_usize;
        let mut concrete_members = 0_usize;
        for member in type_members(class_declaration) {
            if !matches!(member.kind(), "method_declaration" | "property_declaration") {
                continue;
            }
            if has_modifier(&modifiers_of(member, source), "abstract") {
                abstract_members += 1;
            } else {
                concrete_members += 1;
            }
        }
        if abstract_members == 0 || concrete_members == 0 {
            issues.push(issue(
                language,
                "S1694",
                "Make this abstract class declare both abstract and concrete members.",
                range_of(name_anchor(class_declaration), source),
            ));
        }
    }
    issues
}
