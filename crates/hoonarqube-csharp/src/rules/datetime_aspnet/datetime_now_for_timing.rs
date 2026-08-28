use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::operator_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6561 — wall-clock subtraction is unsafe for elapsed-time
/// measurement.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["binary_expression"])
        .into_iter()
        .filter(|expression| {
            !is_error_tainted(*expression)
                && operator_of(*expression) == Some("-")
                && node_text(*expression, source).contains("DateTime.Now")
        })
        .map(|expression| {
            issue(
                language,
                "S6561",
                "Avoid using \"DateTime.Now\" for benchmarking or timespan calculation operations.",
                range_of(expression, source),
            )
        })
        .collect()
}
