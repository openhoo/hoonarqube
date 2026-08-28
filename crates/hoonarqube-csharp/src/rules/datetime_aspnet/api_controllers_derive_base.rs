use super::support::VERB_ATTRIBUTE_NAMES;
use super::support::controller_actions;
use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, issue, node_text, range_of};
use crate::rules::modifiers::has_any_attribute;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6961 — API controllers derive `ControllerBase`, which lacks
/// view support they must never use.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| base_simple_names(*class_node, source).contains(&"Controller"))
        .filter(|class_node| {
            has_any_attribute(*class_node, source, &["ApiController"])
                || controller_actions(*class_node, source)
                    .iter()
                    .any(|action| has_any_attribute(*action, source, &VERB_ATTRIBUTE_NAMES))
        })
        .map(|class_node| {
            let anchor = collect_kinds(class_node, &["identifier"])
                .into_iter()
                .find(|identifier| node_text(*identifier, source) == "Controller")
                .unwrap_or(class_node);
            issue(
                language,
                "S6961",
                "Inherit from ControllerBase instead of Controller.",
                range_of(anchor, source),
            )
        })
        .collect()
}
