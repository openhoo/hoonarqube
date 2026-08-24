use super::support::override_base_pairs;
use super::support::parameter_units;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3600 — overrides introducing `params` where the base has
/// none at that position. Subset: direct file-local bases.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    override_base_pairs(root, source)
        .into_iter()
        .filter_map(|(overriding, base)| {
            let overriding_units = parameter_units(overriding, source);
            let base_units = parameter_units(base, source);
            for (index, unit) in overriding_units.iter().enumerate() {
                if unit.has_params
                    && base_units
                        .get(index)
                        .is_some_and(|base_unit| !base_unit.has_params)
                {
                    return overriding.child_by_field_name("name");
                }
            }
            None
        })
        .map(|name| {
            issue(
                language,
                "S3600",
                "'params' should not be introduced by overrides; remove it from this method.",
                range_of(name),
            )
        })
        .collect()
}
