use super::support::lock_guard_expression;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::enclosing_type;
use crate::rules::logging::field_declarator_names;
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2445 — mutable lock fields invite swapped guards.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for lock_statement in collect_kinds(root, &["lock_statement"]) {
        if is_error_tainted(lock_statement) {
            continue;
        }
        let Some(expression) = lock_guard_expression(lock_statement) else {
            continue;
        };
        if expression.kind() != "identifier" {
            continue;
        }
        let name = node_text(expression, source);
        let Some(owner) = enclosing_type(lock_statement) else {
            continue;
        };
        let field = type_members(owner)
            .into_iter()
            .find(|member| member.kind() == "field_declaration")
            .filter(|field_declaration| {
                field_declarator_names(*field_declaration, source).contains(&name)
            });
        let Some(field) = field else {
            continue;
        };
        if !has_modifier(&modifiers_of(field, source), "readonly") {
            issues.push(issue(
                language,
                "S2445",
                "Declare this lock field 'readonly'.",
                range_of(lock_statement),
            ));
        }
    }
    issues
}
