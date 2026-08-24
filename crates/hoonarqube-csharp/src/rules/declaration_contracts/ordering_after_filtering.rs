use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, receiver_chain_matches};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6607 — filtering after ordering throws away sorted work;
/// filter first.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| {
            callee_name(*invocation, source).is_some_and(|name| name.starts_with("OrderBy"))
        })
        .filter(|invocation| receiver_chain_matches(*invocation, source, |name| name == "Where"))
        .map(|invocation| {
            issue(
                language,
                "S6607",
                "Apply this ordering after filtering.",
                range_of(invocation),
            )
        })
        .collect()
}
