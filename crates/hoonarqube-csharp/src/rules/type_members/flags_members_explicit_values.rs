use super::support::enum_members;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use crate::rules::naming::enum_has_flags_attribute;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2345 — '[Flags]' members without explicit values get
/// powers-of-two-unfriendly implicit numbering.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["enum_declaration"])
        .into_iter()
        .filter(|enum_node| enum_has_flags_attribute(*enum_node, source))
        .filter(|enum_node| {
            enum_members(*enum_node)
                .iter()
                .any(|(_, value)| value.is_none())
        })
        .map(|enum_node| {
            issue(
                language,
                "S2345",
                "Initialize all the members of this 'Flags' enumeration.",
                range_of(name_anchor(enum_node), source),
            )
        })
        .collect()
}
