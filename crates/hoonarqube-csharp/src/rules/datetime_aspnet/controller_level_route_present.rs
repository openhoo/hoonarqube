use super::support::ROUTE_ATTRIBUTE_NAMES;
use super::support::controller_actions;
use crate::CsLanguage;
use crate::cst::{attributes_of, collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::modifiers::has_any_attribute;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6934 — repeating templates on every action signals a missing
/// controller-level '[Route]'.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_node)
            || has_any_attribute(class_node, source, &["Route", "ApiController"])
        {
            continue;
        }
        let action_templates = controller_actions(class_node, source).iter().any(|method| {
            attributes_of(*method, source)
                .iter()
                .any(|name| ROUTE_ATTRIBUTE_NAMES.contains(name))
        });
        if action_templates {
            issues.push(issue(
                language,
                "S6934",
                "Specify the RouteAttribute when an HttpMethodAttribute or RouteAttribute is specified at an action level.",
                range_of(name_anchor(class_node), source),
            ));
        }
    }
    issues
}
