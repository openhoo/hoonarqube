use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2156 — sealed types cannot be inherited from, so their
/// `protected` members are dead weight. `protected override` members are
/// exempt: they exist to satisfy the base contract, and dropping the
/// modifier is a compile error (CS0621).
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
            let member_modifiers = modifiers_of(member, source);
            if has_modifier(&member_modifiers, "override") {
                continue;
            }
            if has_modifier(&member_modifiers, "protected") {
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
