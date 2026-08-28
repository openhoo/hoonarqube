use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2156 — sealed types cannot be inherited from, so their
/// `protected` members are dead weight.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(
        root,
        &[
            "class_declaration",
            "struct_declaration",
            "record_declaration",
        ],
    ) {
        if !has_modifier(&modifiers_of(type_node, source), "sealed") {
            continue;
        }
        for member in type_members(type_node) {
            if has_modifier(&modifiers_of(member, source), "protected") {
                let protected = collect_kinds(member, &["protected"])
                    .into_iter()
                    .next()
                    .unwrap_or(member);
                issues.push(issue(
                    language,
                    "S2156",
                    "Remove this 'protected' modifier.",
                    range_of(protected, source),
                ));
            }
        }
    }
    issues
}
