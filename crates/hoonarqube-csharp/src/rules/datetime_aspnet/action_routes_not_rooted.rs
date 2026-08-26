use super::support::is_route_attribute;
use super::support::route_template_literals;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::declaration_contracts::attribute_applications;
use crate::rules::literals::literal_inner_text;
use crate::rules::security::attributed_declaration;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6931 — action-level route templates starting with '/' escape
/// the controller prefix entirely.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, args, attribute) in attribute_applications(root, source) {
        if !is_route_attribute(name) {
            continue;
        }
        let Some(declaration) = attributed_declaration(attribute) else {
            continue;
        };
        if declaration.kind() != "method_declaration" {
            continue;
        }
        for literal in route_template_literals(args) {
            let template = literal_inner_text(literal, source);
            if template.starts_with('/') && !template.starts_with("~/") {
                issues.push(issue(
                    language,
                    "S6931",
                    "Start this route template without a leading slash.",
                    range_of(attribute, source),
                ));
            }
        }
    }
    issues
}
