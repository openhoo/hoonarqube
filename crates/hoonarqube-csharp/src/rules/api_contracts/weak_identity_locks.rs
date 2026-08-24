use super::support::lock_guard_expression;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["lock_statement"])
        .into_iter()
        .filter(|lock_statement| !is_error_tainted(*lock_statement))
        .filter(|lock_statement| {
            lock_guard_expression(*lock_statement).is_some_and(|expression| {
                matches!(
                    expression.kind(),
                    "this" | "string_literal" | "typeof_expression"
                )
            })
        })
        .map(|lock_statement| {
            issue(
                language,
                "S3998",
                "Lock on a dedicated private lock object.",
                range_of(lock_statement),
            )
        })
        .collect()
}
