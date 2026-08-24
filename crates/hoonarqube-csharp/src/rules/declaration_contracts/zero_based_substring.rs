use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, first_named_child, invocation_arguments};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4635 — `Substring(0, n)` already starts at the beginning.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| callee_name(*invocation, source) == Some("Substring"))
        .filter(|invocation| {
            invocation_arguments(*invocation)
                .first()
                .and_then(|argument| first_named_child(*argument))
                .is_some_and(|value| value.kind() == "integer_literal")
                && invocation_arguments(*invocation)
                    .first()
                    .and_then(|argument| first_named_child(*argument))
                    .is_some_and(|value| node_text(value, source) == "0")
        })
        .map(|invocation| {
            issue(
                language,
                "S4635",
                "Use a start index instead of this zero-based 'Substring'.",
                range_of(invocation),
            )
        })
        .collect()
}
