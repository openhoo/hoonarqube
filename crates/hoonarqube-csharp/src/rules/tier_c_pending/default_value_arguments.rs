use super::support::invocation_is_positional;
use super::support::local_method_table;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use crate::rules::literals::argument_expression;
use crate::rules::tier_c::parameter_units;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3254 — explicit arguments duplicating the callee's parameter
/// default. Subset: fully positional calls against file-local methods; an
/// argument is flagged when its expression text equals the default spelled
/// at the same position of some overload.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let methods = local_method_table(root, source);
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| invocation_is_positional(*call))
        .flat_map(|call| {
            let Some(candidates) = callee_name(call, source).and_then(|name| methods.get(name))
            else {
                return Vec::new();
            };
            let arguments = invocation_arguments(call);
            if arguments.is_empty() {
                return Vec::new();
            }
            arguments
                .into_iter()
                .enumerate()
                .filter(|(index, argument)| {
                    let text = node_text(argument_expression(*argument), source);
                    candidates.iter().any(|method| {
                        parameter_units(*method, source)
                            .get(*index)
                            .and_then(|unit| unit.default_value)
                            .is_some_and(|default| node_text(default, source) == text)
                    })
                })
                .map(|(_, argument)| argument)
                .collect::<Vec<_>>()
        })
        .map(|argument| {
            issue(
                language,
                "S3254",
                "Remove this argument; it duplicates the parameter's default value.",
                range_of(argument),
            )
        })
        .collect()
}
