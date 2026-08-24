use super::support::lock_guard_expression;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::declaration_contracts::enclosing_method;
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6507 — locals are per-call, so locking on them guards
/// nothing shared.
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
        let local_lock = enclosing_method(lock_statement)
            .and_then(|method| body_of(method))
            .is_some_and(|body| {
                collect_kinds(body, &["variable_declarator"])
                    .iter()
                    .any(|declarator| {
                        declarator
                            .child_by_field_name("name")
                            .is_some_and(|declared| node_text(declared, source) == name)
                    })
            });
        if local_lock {
            issues.push(issue(
                language,
                "S6507",
                "Do not lock on this local variable.",
                range_of(lock_statement),
            ));
        }
    }
    issues
}
