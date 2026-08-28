use super::support::VERB_ATTRIBUTE_NAMES;
use super::support::controller_actions;
use super::support::is_api_controller_like;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use crate::rules::modifiers::has_any_attribute;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6965 — actions without an HTTP verb annotation answer every
/// verb, including the dangerous ones.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| {
            is_api_controller_like(*class_node, source)
                && has_any_attribute(*class_node, source, &["ApiController"])
        })
        .flat_map(|class_node| controller_actions(class_node, source))
        .filter(|action| !has_any_attribute(*action, source, &VERB_ATTRIBUTE_NAMES))
        .map(|action| {
            issue(
                language,
                "S6965",
                "REST API controller actions should be annotated with the appropriate HTTP verb attribute.",
                range_of(name_anchor(action), source),
            )
        })
        .collect()
}
