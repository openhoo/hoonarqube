use super::support::{is_route_attribute, route_template_literals};
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use crate::rules::declaration_contracts::attribute_applications;
use crate::rules::expressions::enclosing_type;
use crate::rules::literals::literal_inner_text;
use crate::rules::security::attributed_declaration;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6931 — absolute action routes override the controller route.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut bad_controllers = std::collections::HashSet::new();
    for (name, args, attribute) in attribute_applications(root, source) {
        if !is_route_attribute(name) {
            continue;
        }
        let Some(declaration) = attributed_declaration(attribute) else {
            continue;
        };
        if declaration.kind() != "method_declaration"
            || !route_template_literals(args).into_iter().any(|literal| {
                let template = literal_inner_text(literal, source);
                template.starts_with('/') && !template.starts_with("~/")
            })
        {
            continue;
        }
        if let Some(controller) = enclosing_type(declaration) {
            bad_controllers.insert(controller.id());
        }
    }

    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| bad_controllers.contains(&class_node.id()))
        .map(|class_node| {
            issue(
                language,
                "S6931",
                "Change the paths of the actions of this controller to be relative and adapt the controller route accordingly.",
                range_of(name_anchor(class_node), source),
            )
        })
        .collect()
}
