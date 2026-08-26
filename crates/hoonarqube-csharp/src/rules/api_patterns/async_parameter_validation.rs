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
        let Some(first_await) = collect_kinds(body, &["await_expression"])
            .into_iter()
            .map(|await_expression| await_expression.start_byte())
            .min()
        else {
            continue;
        };
        for validation in validation_statements(body, source) {
            if validation.start_byte() > first_await {
                issues.push(issue(
                    language,
                    "S4457",
                    "Validate these parameters before the first 'await' in this method.",
                    range_of(validation, source),
                ));
            }
        }
    }
    issues
}
