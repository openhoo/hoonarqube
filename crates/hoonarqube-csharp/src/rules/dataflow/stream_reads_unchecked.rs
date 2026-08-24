use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, first_named_child};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2674 — a stream read's return value says how many bytes
/// landed; discarding it invites stale-buffer bugs. Bound: only fully
/// discarded results are flagged — comparing the count correctly needs
/// value-flow this pass does not model.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["expression_statement"])
        .into_iter()
        .filter(|statement| !is_error_tainted(*statement))
        .filter_map(|statement| first_named_child(statement))
        .filter(|expression| {
            expression.kind() == "invocation_expression"
                && STREAM_READ_METHODS.contains(&callee_name(*expression, source).unwrap_or(""))
        })
        .map(|call| {
            issue(
                language,
                "S2674",
                "Check the value returned by this stream read.",
                range_of(call),
            )
        })
        .collect()
}

/// Stream reads whose returned length matters.
const STREAM_READ_METHODS: [&str; 3] = ["Read", "ReadBlock", "ReadAsync"];
