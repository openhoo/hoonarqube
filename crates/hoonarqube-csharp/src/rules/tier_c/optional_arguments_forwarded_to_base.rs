use super::support::parameter_default_value;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of};
use crate::rules::declaration_contracts::enclosing_method;
use crate::rules::expressions::{invocation_arguments, invocation_function};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3466 — calls into `base.` members that repeat an optional
/// parameter of the enclosing member purely to hand back its default.
/// Subset: textual `base.` receivers and identifier arguments matching a
/// defaulted parameter name of the enclosing callable.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            invocation_function(*call)
                .is_some_and(|function| node_text(function, source).trim().starts_with("base."))
        })
        .filter_map(|call| {
            let enclosing = enclosing_method(call)?;
            let defaulted: std::collections::HashSet<&str> = parameters_of(enclosing)
                .into_iter()
                .filter(|parameter| parameter_default_value(*parameter).is_some())
                .filter_map(|parameter| parameter.child_by_field_name("name"))
                .map(|name| node_text(name, source))
                .collect();
            (!defaulted.is_empty()).then_some((call, defaulted))
        })
        .filter(|(call, defaulted)| {
            invocation_arguments(*call).into_iter().any(|argument| {
                let expression = argument_expression(argument);
                expression.kind() == "identifier"
                    && defaulted.contains(node_text(expression, source))
            })
        })
        .map(|(call, _)| {
            issue(
                language,
                "S3466",
                "Omit this argument; the base declaration already makes it optional.",
                range_of(call),
            )
        })
        .collect()
}
