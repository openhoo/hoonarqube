use super::support::enum_members;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::expressions::integer_literal_value;
use crate::rules::naming::enum_has_flags_attribute;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2346 — the zero value of a '[Flags]' enumeration means 'no
/// options' and should be named 'None'.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["enum_declaration"])
        .into_iter()
        .filter(|enum_node| enum_has_flags_attribute(*enum_node, source))
        .flat_map(|enum_node| {
            let members = enum_members(enum_node);
            // Explicit zero wins; otherwise an uninitialized first member is
            // implicitly zero.
            let zero = members.iter().find_map(|(_, value)| {
                value
                    .and_then(|node| integer_literal_value(node_text(node, source)))
                    .filter(|parsed| *parsed == 0)
            });
            let zero_member = zero.and_then(|_| {
                members.iter().find(|(_, value)| {
                    value.and_then(|node| integer_literal_value(node_text(node, source))) == Some(0)
                })
            });
            let candidate = match (zero_member, members.first()) {
                (Some((_, _)), _) => Some(zero_member.unwrap().0),
                (None, Some((first, None))) if members.len() > 1 => Some(*first),
                _ => None,
            };
            candidate.into_iter()
        })
        .filter_map(|member| member.child_by_field_name("name"))
        .filter(|name| !node_text(*name, source).eq_ignore_ascii_case("none"))
        .map(|name| {
            issue(
                language,
                "S2346",
                format!(
                    "Name this zero-valued '[Flags]' member '{}' 'None' instead.",
                    node_text(name, source)
                ),
                range_of(name),
            )
        })
        .collect()
}
