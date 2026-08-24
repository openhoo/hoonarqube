use super::support::override_base_pairs;
use crate::CsLanguage;
use crate::cst::{issue, modifiers_of, range_of};
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4015 — overrides narrowing the overridden member's
/// visibility. Subset: both sides declare explicit modifiers on a direct
/// file-local base; undeclared (contextual default) pairs stay untouched.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    override_base_pairs(root, source)
        .into_iter()
        .filter_map(|(overriding, base)| {
            let derived_rank = declared_visibility_rank(&modifiers_of(overriding, source))?;
            let base_rank = declared_visibility_rank(&modifiers_of(base, source))?;
            (derived_rank < base_rank)
                .then(|| overriding.child_by_field_name("name"))
                .flatten()
        })
        .map(|name| {
            issue(
                language,
                "S4015",
                "Do not decrease the visibility of this overridden member.",
                range_of(name),
            )
        })
        .collect()
}

/// Simplified C# accessibility ladder for declared member modifiers.
fn declared_visibility_rank(modifiers: &[&str]) -> Option<i32> {
    let has = |wanted: &str| has_modifier(modifiers, wanted);
    if has("public") {
        Some(6)
    } else if has("protected") && has("internal") {
        Some(5)
    } else if has("internal") {
        Some(4)
    } else if has("protected") {
        if has("private") { Some(2) } else { Some(3) }
    } else if has("private") {
        Some(1)
    } else {
        None
    }
}
