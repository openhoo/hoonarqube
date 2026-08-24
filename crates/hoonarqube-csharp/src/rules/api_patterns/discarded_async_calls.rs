use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, first_named_child};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6966 — fire-and-forget async work dies unobserved and
/// swallows failures. Bound: convention — methods named `*Async` called
/// as bare statements are treated as awaitable.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["expression_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter_map(|statement| first_named_child(statement))
        .filter(|expression| expression.kind() == "invocation_expression")
        .filter(|call| callee_name(*call, source).is_some_and(|name| name.ends_with("Async")))
        .map(|call| {
            issue(
                language,
                "S6966",
                "Await this asynchronous operation or observe its result.",
                range_of(call),
            )
        })
        .collect()
}
