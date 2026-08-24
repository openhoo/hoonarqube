use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, invocation_arguments, invocation_receiver};
use crate::rules::literals::argument_expression;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2114 — a collection passed as an argument to its own
/// mutating/search method (`list.AddRange(list)`). Subset: plain identifier
/// receivers matched textually against identifier arguments; property chains
/// and aliased references stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const SAME_COLLECTION_METHODS: [&str; 7] = [
        "AddRange",
        "InsertRange",
        "CopyTo",
        "Concat",
        "Union",
        "Intersect",
        "Except",
    ];
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|call| !is_error_tainted(*call))
        .filter(|call| {
            callee_name(*call, source)
                .is_some_and(|callee| SAME_COLLECTION_METHODS.contains(&callee))
        })
        .filter(|call| {
            invocation_receiver(*call).is_some_and(|receiver| receiver.kind() == "identifier")
        })
        .filter(|call| {
            let Some(receiver) = invocation_receiver(*call) else {
                return false;
            };
            let receiver_text = node_text(receiver, source);
            invocation_arguments(*call).into_iter().any(|argument| {
                let expression = argument_expression(argument);
                expression.kind() == "identifier" && node_text(expression, source) == receiver_text
            })
        })
        .map(|call| {
            issue(
                language,
                "S2114",
                "Pass a different collection than the receiver to this method.",
                range_of(call),
            )
        })
        .collect()
}
