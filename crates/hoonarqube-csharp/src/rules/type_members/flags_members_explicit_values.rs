use super::support::enum_members;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::naming::enum_has_flags_attribute;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2345 — '[Flags]' members without explicit values get
/// powers-of-two-unfriendly implicit numbering.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["enum_declaration"])
        .into_iter()
        .filter(|enum_node| enum_has_flags_attribute(*enum_node, source))
        .flat_map(|enum_node| enum_members(enum_node))
        .filter_map(|(member, value)| {
            let name = member.child_by_field_name("name")?;
            value.is_none().then_some(name)
        })
        .map(|name| {
            issue(
                language,
                "S2345",
                format!(
                    "Give the enumeration member '{}' an explicit value.",
                    node_text(name, source)
                ),
                range_of(name, source),
            )
        })
        .collect()
}
