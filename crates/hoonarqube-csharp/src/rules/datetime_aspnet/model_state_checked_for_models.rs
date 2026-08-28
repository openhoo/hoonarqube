use super::support::controller_actions;
use super::support::is_api_controller_like;
use crate::CsLanguage;
use crate::cst::{attributes_of, collect_kinds, issue, node_text, parameters_of, range_of};
use crate::rules::modifiers::has_any_attribute;
use crate::rules::structure::{body_of, name_anchor};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6967 — actions receiving models must gate their use behind
/// 'ModelState.IsValid'.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| is_api_controller_like(*class_node, source))
        .filter(|class_node| !has_any_attribute(*class_node, source, &["ApiController"]))
        .flat_map(|class_node| controller_actions(class_node, source))
        .filter(|action| {
            parameters_of(*action).iter().any(|parameter| {
                parameter
                    .child_by_field_name("type")
                    .is_some_and(|ty| model_has_validation(root, node_text(ty, source), source))
            })
        })
        .filter(|action| {
            body_of(*action)
                .is_none_or(|body| !node_text(body, source).contains("ModelState.IsValid"))
        })
        .map(|action| {
            issue(
                language,
                "S6967",
                "ModelState.IsValid should be checked in controller actions.",
                range_of(name_anchor(action), source),
            )
        })
        .collect()
}

fn model_has_validation(root: Node<'_>, type_name: &str, source: &str) -> bool {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| {
            class_node
                .child_by_field_name("name")
                .is_some_and(|name| node_text(name, source) == type_name)
        })
        .flat_map(|class_node| collect_kinds(class_node, &["property_declaration"]))
        .any(|property| !attributes_of(property, source).is_empty())
}
