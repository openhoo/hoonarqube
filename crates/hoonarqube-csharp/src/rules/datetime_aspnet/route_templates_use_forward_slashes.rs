use super::support::is_route_attribute;
use super::support::route_template_literals;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::declaration_contracts::attribute_applications;
use crate::rules::literals::literal_inner_text;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6930 — backslashes break route templates on every platform
/// but Windows.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    attribute_applications(root, source)
        .into_iter()
        .filter(|(name, _, _)| is_route_attribute(name))
        .flat_map(|(_, args, _)| route_template_literals(args))
        .filter(|literal| literal_inner_text(*literal, source).contains('\\'))
        .map(|literal| {
            issue(
                language,
                "S6930",
                "Use forward slashes in this route template.",
                range_of(literal),
            )
        })
        .collect()
}
