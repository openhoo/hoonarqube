use super::support::validation_statements;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4457 — async methods should reject bad input before the
/// first suspension point; validations after an `await` surface late.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !has_modifier(&modifiers_of(method, source), "async") {
            continue;
        }
        let Some(body) = body_of(method) else {
            continue;
        };
        if collect_kinds(body, &["await_expression"]).is_empty()
            || validation_statements(body, source).is_empty()
        {
            continue;
        }
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S4457",
            "Split this method into two, one handling parameters check and the other handling the asynchronous code.",
            range_of(name, source),
        ));
    }
    issues
}
