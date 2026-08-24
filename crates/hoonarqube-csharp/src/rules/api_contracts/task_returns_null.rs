use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, range_of, simple_name};
use crate::rules::expressions::first_named_child;
use crate::rules::modifiers::has_modifier;
use crate::rules::security::return_type_text;
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4586 — non-async `Task` methods must not return null; there
/// is no completed task to await in null.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) || has_modifier(&modifiers_of(method, source), "async") {
            continue;
        }
        if simple_name(return_type_text(method, source)) != "Task" {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        for statement in collect_kinds(body, &["return_statement"]) {
            let returns_null = first_named_child(statement)
                .is_some_and(|expression| expression.kind() == "null_literal");
            if returns_null {
                issues.push(issue(
                    language,
                    "S4586",
                    "Return 'Task.CompletedTask' instead of null.",
                    range_of(statement),
                ));
            }
        }
    }
    issues
}
