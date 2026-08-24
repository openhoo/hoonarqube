use super::support::override_base_pairs;
use super::support::parameter_units;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3262 — overrides dropping the `params` modifier their base
/// declares at the same parameter position. Subset: direct file-local bases.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    override_base_pairs(root, source)
        .into_iter()
        .filter_map(|(overriding, base)| {
            let overriding_units = parameter_units(overriding, source);
            for (index, base_unit) in parameter_units(base, source).iter().enumerate() {
                if base_unit.has_params {
                    match overriding_units.get(index) {
                        Some(unit) if !unit.has_params => {
                            return overriding.child_by_field_name("name");
                        }
                        _ => {}
                    }
                }
            }
            None
        })
        .map(|name| {
            issue(
                language,
                "S3262",
                "Add 'params' to this override to match the base declaration.",
                range_of(name),
            )
        })
        .collect()
}
