use super::support::VERB_ATTRIBUTE_NAMES;
use super::support::controller_actions;
use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, issue, range_of};
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
            issue(
                language,
                "S6961",
                "Derive API controllers from 'ControllerBase'.",
                range_of(class_node),
            )
        })
        .collect()
}
