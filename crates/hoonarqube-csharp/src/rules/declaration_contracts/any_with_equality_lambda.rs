use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{
    binary_operands, callee_name, expression_name, first_named_child, invocation_arguments,
    lambda_shape, operator_of,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6617 — `Any(x => x == y)` scans until equality; `Contains`
/// states the intent and optimizes.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    /// Whether the lambda body compares its parameter against something.
    fn parameter_equality(body: Node<'_>, parameter: &str, source: &str) -> bool {
        body.kind() == "binary_expression"
            && operator_of(body) == Some("==")
            && binary_operands(body).is_some_and(|(left, right)| {
                [left, right]
                    .iter()
                    .any(|operand| expression_name(*operand, source) == Some(parameter))
            })
    }

    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| matches!(callee_name(*invocation, source), Some("Any" | "All")))
        .filter(
            |invocation| match invocation_arguments(*invocation).as_slice() {
                [only] => first_named_child(*only)
                    .and_then(|lambda| (lambda.kind() == "lambda_expression").then_some(lambda))
                    .and_then(|lambda| lambda_shape(lambda, source))
                    .is_some_and(|(parameter, body)| parameter_equality(body, parameter, source)),
                _ => false,
            },
        )
        .map(|invocation| {
            issue(
                language,
                "S6617",
                "Use 'Contains' instead of this equality lambda.",
                range_of(invocation),
            )
        })
        .collect()
}
