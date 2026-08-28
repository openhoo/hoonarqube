use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4016 — members named 'Reserved' promise nothing and invite
/// cargo-cult extensions.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["enum_declaration"])
        .into_iter()
        .flat_map(|enum_node| collect_kinds(enum_node, &["enum_member_declaration"]))
        .filter(|member| {
            member
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source).eq_ignore_ascii_case("reserved"))
        })
        .map(|member| {
            issue(
                language,
                "S4016",
                "Remove or rename this enum member.",
                range_of(member, source),
            )
        })
        .collect()
}
