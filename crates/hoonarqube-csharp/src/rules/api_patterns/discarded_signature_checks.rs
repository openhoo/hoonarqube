use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6377 — an XML signature check nobody acts on protects
/// nothing. Bound: discarded `CheckSignature` results.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| callee_name(*call, source) == Some("CheckSignature"))
        .filter(|call| invocation_arguments(*call).is_empty())
        .map(|call| {
            issue(
                language,
                "S6377",
                "Change this code to only accept signatures computed from a trusted party.",
                range_of(call, source),
            )
        })
        .collect()
}
