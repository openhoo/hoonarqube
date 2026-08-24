use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, first_named_child};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6377 — an XML signature check nobody acts on protects
/// nothing. Bound: discarded `CheckSignature` results.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["expression_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter_map(|statement| first_named_child(statement))
        .filter(|expression| {
            expression.kind() == "invocation_expression"
                && callee_name(*expression, source) == Some("CheckSignature")
        })
        .map(|call| {
            issue(
                language,
                "S6377",
                "Act on the result of this signature validation.",
                range_of(call),
            )
        })
        .collect()
}
