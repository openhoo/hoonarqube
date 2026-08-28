use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_from_byte_offsets};
use crate::rules::expressions::invocation_arguments;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4220 — instance events must be raised with a non-null sender.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| {
            !is_error_tainted(*call)
                && node_text(*call, source)
                    .split_once('(')
                    .is_some_and(|(callee, _)| callee.trim_end().ends_with("Invoke"))
        })
        .filter(|call| {
            invocation_arguments(*call)
                .first()
                .is_some_and(|argument| node_text(*argument, source) == "null")
        })
        .map(|call| {
            let call_text = node_text(call, source);
            let start = call_text
                .find(".Invoke")
                .map_or(call.start_byte(), |offset| call.start_byte() + offset);
            issue(
                language,
                "S4220",
                "Make the sender on this event invocation not null.",
                range_from_byte_offsets(start, call.end_byte(), source),
            )
        })
        .collect()
}
