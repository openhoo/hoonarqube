use super::support::VERB_ATTRIBUTE_NAMES;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use crate::rules::modifiers::has_any_attribute;
use crate::rules::security::return_type_text;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6968 — declared success responses keep generated clients
/// honest about what an action returns.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["method_declaration"])
        .into_iter()
        .filter(|action| has_any_attribute(*action, source, &VERB_ATTRIBUTE_NAMES))
        .filter(|action| return_type_text(*action, source) != "void")
        .filter(|action| !has_any_attribute(*action, source, &["ProducesResponseType"]))
        .map(|action| {
            issue(
                language,
                "S6968",
                "Declare '[ProducesResponseType]' for this action's responses.",
                range_of(name_anchor(action), source),
            )
        })
        .collect()
}
