use super::support::local_method_table;
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of, simple_name,
};
use crate::rules::expressions::{callee_name, invocation_arguments};
use crate::rules::literals::argument_expression;
use crate::rules::tier_c::parameter_units;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3220 — calls resolving ambiguously to a `params` overload.
/// Subset: invocations whose last argument is an explicit array creation
/// while the callee name declares both a `params` overload and a
/// same-arity non-`params` overload whose last parameter is array- or
/// object-typed. Other ambiguity shapes stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let methods = local_method_table(root, source);
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            let Some(candidates) = callee_name(*call, source).and_then(|name| methods.get(name))
            else {
                return false;
            };
            let argument_count = invocation_arguments(*call).len();
            let has_params = candidates.iter().any(|method| {
                parameter_units(*method, source)
                    .iter()
                    .any(|unit| unit.has_params)
            });
            let has_plain_candidate = candidates.iter().any(|method| {
                let parameters = parameters_of(*method);
                parameters.len() == argument_count
                    && parameters
                        .last()
                        .is_some_and(|last| parameter_binds_arrays(*last, source))
                    && !parameter_units(*method, source)
                        .iter()
                        .any(|unit| unit.has_params)
            });
            has_params && has_plain_candidate
        })
        .filter(|call| {
            invocation_arguments(*call).last().is_some_and(|argument| {
                matches!(
                    argument_expression(*argument).kind(),
                    "array_creation_expression" | "implicit_array_creation_expression"
                )
            })
        })
        .map(|call| {
            issue(
                language,
                "S3220",
                "This call resolves to the 'params' overload; make the intended overload explicit.",
                range_of(call),
            )
        })
        .collect()
}

/// Whether a proper `parameter` could bind an explicit array argument: an
/// array-typed spelling, or `object`/`dynamic`.
fn parameter_binds_arrays(parameter: Node<'_>, source: &str) -> bool {
    parameter
        .child_by_field_name("type")
        .map(|type_node| node_text(type_node, source))
        .is_some_and(|text| {
            text.ends_with("[]") || matches!(simple_name(text), "object" | "Object" | "dynamic")
        })
}
