use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{
    callee_name, expression_name, invocation_arguments, invocation_receiver,
};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4057 — single-argument `Convert.To*` calls parse with
/// the machine culture; data conversions need an explicit format
/// provider. Overload resolution is approximated by argument count.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            invocation_receiver(*call)
                .is_some_and(|receiver| expression_name(receiver, source) == Some("Convert"))
                && callee_name(*call, source).is_some_and(|name| name.starts_with("To"))
        })
        .filter(|call| invocation_arguments(*call).len() == 1)
        .map(|call| {
            issue(
                language,
                "S4057",
                "Pass an 'IFormatProvider' to make this conversion culture-independent.",
                range_of(call, source),
            )
        })
        .collect()
}
