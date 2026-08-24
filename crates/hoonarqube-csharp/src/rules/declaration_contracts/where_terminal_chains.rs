use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, invocation_receiver};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2971 — a `Where` feeding a terminal LINQ operator folds into
/// that operator's predicate overload.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const TERMINALS: [&str; 8] = [
        "Any",
        "Count",
        "First",
        "FirstOrDefault",
        "Last",
        "LastOrDefault",
        "Single",
        "SingleOrDefault",
    ];
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| TERMINALS.contains(&callee_name(*invocation, source).unwrap_or("")))
        .filter(|invocation| {
            invocation_receiver(*invocation).and_then(|receiver| callee_name(receiver, source))
                == Some("Where")
        })
        .map(|invocation| {
            issue(
                language,
                "S2971",
                "Move this filter into the terminal LINQ call's predicate.",
                range_of(invocation),
            )
        })
        .collect()
}
