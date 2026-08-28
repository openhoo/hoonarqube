use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use crate::rules::literals::{argument_expression, literal_inner_text};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6585 — hard-coded date format strings ignore the user's
/// culture; pass a provider or use the invariant one deliberately.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    /// Distinctive date/time pattern tokens (`MM` differs from `mm`).
    const DATE_FORMAT_TOKENS: [&str; 12] = [
        "yyyy", "yyy", "MMMM", "MMM", "dddd", "ddd", "MM", "dd", "HH", "hh", "mm", "ss",
    ];
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| callee_name(*invocation, source) == Some("ToString"))
        .filter_map(|invocation| invocation_arguments(invocation).first().copied())
        .map(argument_expression)
        .filter(|argument| argument.kind() == "string_literal")
        .filter(|argument| {
            let text = literal_inner_text(*argument, source);
            DATE_FORMAT_TOKENS.iter().any(|token| text.contains(token))
        })
        .map(|argument| {
            issue(
                language,
                "S6585",
                "Do not hardcode the format specifier.",
                range_of(argument, source),
            )
        })
        .collect()
}
