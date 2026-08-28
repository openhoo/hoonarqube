use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use crate::rules::expressions::enclosing_type;
use crate::rules::modifiers::type_declared_rank;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1104 — publicly accessible instance fields break
/// encapsulation; static and constant members belong to S2223 and S2339.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        if has_modifier(&modifiers, "public")
            && !has_modifier(&modifiers, "static")
            && !has_modifier(&modifiers, "const")
            && enclosing_type(field)
                .is_some_and(|type_node| type_declared_rank(type_node, source) == 6)
        {
            for declarator in collect_kinds(field, &["variable_declarator"]) {
                let name = declarator.child_by_field_name("name").unwrap_or(declarator);
                let range = if declarator.named_child_count().gt(&1) {
                    range_of(declarator, source)
                } else {
                    range_of(name, source)
                };
                issues.push(issue(
                    language,
                    "S1104",
                    "Make this field 'private' and encapsulate it in a 'public' property.",
                    range,
                ));
            }
        }
    }
    issues
}
