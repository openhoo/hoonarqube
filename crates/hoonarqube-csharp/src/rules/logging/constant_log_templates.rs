use super::support::logging_calls;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::invocation_arguments;
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2629 — interpolated or computed templates defeat structured
/// logging; only constant templates can be parsed by log backends.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    logging_calls(root, source)
        .into_iter()
        .filter_map(|call| {
            invocation_arguments(call)
                .first()
                .copied()
                .map(|first| (call, argument_expression(first)))
        })
        .filter(|(_, expression)| expression.kind() != "string_literal")
        .map(|(_, expression)| {
            let message = if expression.kind() == "interpolated_string_expression" {
                "Don't use string interpolation in logging message templates."
            } else {
                "Don't use string concatenation in logging message templates."
            };
            issue(language, "S2629", message, range_of(expression, source))
        })
        .collect()
}
