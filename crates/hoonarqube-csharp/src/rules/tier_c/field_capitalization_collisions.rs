use super::support::shadowed_field_sites;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4025 — child fields differing from a parent field only by
/// capitalization. Subset: direct file-local base classes.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    shadowed_field_sites(root, source)
        .into_iter()
        .filter(|(derived, _, base)| derived != base && derived.eq_ignore_ascii_case(base))
        .map(|(_, node, _)| {
            issue(
                language,
                "S4025",
                "Rename this field; it differs from an inherited field only by capitalization.",
                range_of(node),
            )
        })
        .collect()
}
