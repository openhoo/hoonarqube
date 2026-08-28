use super::support::accessibility_rank;
use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::enclosing_type;
use crate::rules::modifiers::type_declared_rank;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2357 — fields should be private; constants are S2339's
/// territory.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        let real_public = accessibility_rank(&modifiers) == 6
            && enclosing_type(field)
                .is_some_and(|type_node| type_declared_rank(type_node, source) == 6);
        if !has_modifier(&modifiers, "const") && !has_modifier(&modifiers, "static") && real_public
        {
            for declarator in collect_kinds(field, &["variable_declarator"]) {
                let name = declarator.child_by_field_name("name").unwrap_or(declarator);
                issues.push(issue(
                    language,
                    "S2357",
                    format!("Make '{}' private.", node_text(name, source)),
                    range_of(name, source),
                ));
            }
        }
    }
    issues
}
