use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3442 — abstract classes are constructed through derived
/// types, so public constructors mislead callers.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &["class_declaration", "record_declaration"]) {
        if !has_modifier(&modifiers_of(type_node, source), "abstract") {
            continue;
        }
        for member in type_members(type_node) {
            if member.kind() == "constructor_declaration"
                && has_modifier(&modifiers_of(member, source), "public")
            {
                let public_keyword = collect_kinds(member, &["public"])
                    .into_iter()
                    .next()
                    .unwrap_or(member);
                issues.push(issue(
                    language,
                    "S3442",
                    "Change the visibility of this constructor to 'protected'.",
                    range_of(public_keyword, source),
                ));
            }
        }
    }
    issues
}
