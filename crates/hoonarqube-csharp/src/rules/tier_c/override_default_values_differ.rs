use super::support::override_base_pairs;
use super::support::parameter_units;
use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1006 — overrides changing a base method's default value.
/// Subset: positional comparison of parameters where BOTH sides spell out a
/// default; missing defaults on either side stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    override_base_pairs(root, source)
        .into_iter()
        .filter_map(|(overriding, base)| {
            let overriding_parameters = parameter_units(overriding, source);
            let base_parameters = parameter_units(base, source);
            for (index, unit) in overriding_parameters.iter().enumerate() {
                let Some(base_unit) = base_parameters.get(index) else {
                    break;
                };
                if let (Some(value), Some(base_value)) =
                    (unit.default_value, base_unit.default_value)
                    && node_text(value, source) != node_text(base_value, source)
                {
                    return overriding.child_by_field_name("name");
                }
            }
            None
        })
        .map(|name| {
            issue(
                language,
                "S1006",
                "Make this override's default value match the overridden method.",
                range_of(name),
            )
        })
        .collect()
}
