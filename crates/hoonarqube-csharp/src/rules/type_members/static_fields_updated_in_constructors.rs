use super::support::assigned_names;
use super::support::static_field_declarators;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3010 — instance constructors updating static fields leak
/// state across instances.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        let static_names: std::collections::HashSet<&str> =
            static_field_declarators(type_node, source)
                .into_iter()
                .filter_map(|declarator| {
                    declarator
                        .child_by_field_name("name")
                        .map(|name| node_text(name, source))
                })
                .collect();
        if static_names.is_empty() {
            continue;
        }
        for ctor in member_declarations_of_kind(type_node, "constructor_declaration") {
            if has_modifier(&modifiers_of(ctor, source), "static") {
                continue; // static constructors are the right place
            }
            let Some(body) = ctor.child_by_field_name("body") else {
                continue;
            };
            for assignment in collect_kinds(body, &["assignment_expression"]) {
                if let Some(name) = assigned_names(assignment, source)
                    .first()
                    .filter(|name| static_names.contains(*name))
                {
                    issues.push(issue(
                        language,
                        "S3010",
                        format!(
                            "Do not assign the static field '{name}' from an instance constructor."
                        ),
                        range_of(assignment),
                    ));
                }
            }
        }
    }
    issues
}
