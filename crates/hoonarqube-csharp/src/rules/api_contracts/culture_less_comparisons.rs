use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4058 — two-operand comparisons silently use the current
/// culture instead of a stated comparison mode.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            matches!(callee_name(*call, source), Some("Compare" | "Equals"))
                && invocation_arguments(*call).len() == 2
        })
        .map(|call| {
            issue(
                language,
                "S4058",
                "Use the 'StringComparison' overload of this comparison.",
                range_of(call),
            )
        })
        .collect()
}
