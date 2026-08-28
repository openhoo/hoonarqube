use super::support::body_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::modifiers::subtree_contains_kind;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1048 — finalizers do not throw.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for destructor in collect_kinds(root, &["destructor_declaration"]) {
        if is_error_tainted(destructor) {
            continue;
        }
        let Some(body) = body_of(destructor) else {
            continue;
        };
        if subtree_contains_kind(body, "throw_statement")
            && let Some(throw_statement) =
                collect_kinds(body, &["throw_statement"]).into_iter().next()
        {
            issues.push(issue(
                language,
                "S1048",
                "Remove this 'throw' statement.",
                range_of(throw_statement, source),
            ));
        }
    }
    issues
}
