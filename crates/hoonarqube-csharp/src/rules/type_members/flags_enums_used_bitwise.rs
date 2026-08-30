use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::naming::enum_has_flags_attribute;
use crate::rules::structure::name_anchor;
use crate::rules::type_members::support::enum_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4070 — externally visible `[Flags]` enum values must be
/// powers of two or combinations of values already defined.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["enum_declaration"])
        .into_iter()
        .filter(|enum_node| enum_has_flags_attribute(*enum_node, source))
        .filter(|enum_node| has_invalid_flags_value(*enum_node, source))
        .map(|enum_node| {
            issue(
                language,
                "S4070",
                "Remove the 'FlagsAttribute' from this enum.",
                range_of(name_anchor(enum_node), source),
            )
        })
        .collect()
}

fn has_invalid_flags_value(enum_node: Node<'_>, source: &str) -> bool {
    let mut available_bits = 0_u128;
    for (_, value_node) in enum_members(enum_node) {
        let Some(value_node) = value_node else {
            continue;
        };
        let text = node_text(value_node, source).replace('_', "");
        let value = text
            .strip_prefix("0x")
            .and_then(|hex| u128::from_str_radix(hex, 16).ok())
            .or_else(|| text.parse::<u128>().ok());
        let Some(value) = value else {
            continue;
        };
        if value == 0 {
            continue;
        }
        if value.is_power_of_two() {
            available_bits |= value;
            continue;
        }
        if value & !available_bits != 0 {
            return true;
        }
    }
    false
}
