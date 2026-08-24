use super::support::assigned_names;
use super::support::static_field_declarators;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::literals::declarator_initializer;
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3963 — static fields assigned only inside the static
/// constructor belong inline with their declarations.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let static_ctor = member_declarations_of_kind(type_node, "constructor_declaration")
            .into_iter()
            .filter(|ctor| has_modifier(&modifiers_of(*ctor, source), "static"))
            .find_map(|ctor| ctor.child_by_field_name("body").map(|body| (ctor, body)));
        let Some((_, body)) = static_ctor else {
            continue;
        };
        let assigned: std::collections::HashSet<&str> =
            assigned_names(body, source).into_iter().collect();
        if assigned.is_empty() {
            continue;
        }
        for declarator in static_field_declarators(type_node, source) {
            let Some(name_node) = declarator.child_by_field_name("name") else {
                continue;
            };
            let name = node_text(name_node, source);
            if assigned.contains(name) && declarator_initializer(declarator, name_node).is_none() {
                issues.push(issue(
                    language,
                    "S3963",
                    format!("Initialize '{name}' inline instead of in the static constructor."),
                    range_of(name_node),
                ));
            }
        }
    }
    issues
}
