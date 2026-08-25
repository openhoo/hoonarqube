use super::support::matched_method_pairs;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::modifiers::has_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    matched_method_pairs(root, source, |modifiers| {
        !has_modifier(modifiers, "override") && !has_modifier(modifiers, "new")
    })
    .into_iter()
    .filter_map(|(hiding, _)| hiding.child_by_field_name("name"))
    .map(|name| {
        issue(
            language,
            "S4019",
            "Declare this method 'new' or rename it; it hides an inherited member.",
            range_of(name),
        )
    })
    .collect()
}
