use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, first_named_child, invocation_arguments};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3216 — `ConfigureAwait(true)` is the default and only adds
/// noise; capture the context deliberately with `false`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| callee_name(*invocation, source) == Some("ConfigureAwait"))
        .filter(|invocation| {
            invocation_arguments(*invocation).iter().any(|argument| {
                first_named_child(*argument).is_some_and(|value| node_text(value, source) == "true")
            })
        })
        .map(|invocation| {
            issue(
                language,
                "S3216",
                "Pass 'false' to 'ConfigureAwait'.",
                range_of(invocation),
            )
        })
        .collect()
}
