use super::support::{field_declarators, has_modifier};
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use crate::rules::expressions::enclosing_type;
use crate::rules::modifiers::type_declared_rank;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2339 — public constants leak implementation details into
/// every referencing assembly.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for field in collect_kinds(root, &["field_declaration"]) {
        let modifiers = modifiers_of(field, source);
        if has_modifier(&modifiers, "const")
            && has_modifier(&modifiers, "public")
            && enclosing_type(field)
                .is_some_and(|type_node| type_declared_rank(type_node, source) == 6)
        {
            for declarator in field_declarators(field) {
                let name = declarator.child_by_field_name("name").unwrap_or(declarator);
                issues.push(issue(
                    language,
                    "S2339",
                    "Change this constant to a 'static' read-only property.",
                    range_of(name, source),
                ));
            }
        }
    }
    issues
}
