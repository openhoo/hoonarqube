use super::support::shadowed_field_sites;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2387 — child fields hiding a same-named parent field.
/// Subset: exact-name collisions against a direct file-local base class.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    shadowed_field_sites(root, source)
        .into_iter()
        .filter(|(derived, _, base)| derived == base)
        .map(|(_, node, _)| {
            issue(
                language,
                "S2387",
                "Rename this field; it hides the field declared in its base class.",
                range_of(node),
            )
        })
        .collect()
}
