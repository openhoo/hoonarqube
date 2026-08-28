use super::support::azure_function_classes;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, expression_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6422 — blocking on async work inside a Function deadlocks
/// the single-invocation host.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    azure_function_classes(root, source)
        .into_iter()
        .flat_map(|class_node| blocking_calls_in_scope(class_node, source))
        .map(|call| {
            let member = expression_name(call, source).unwrap_or("Result");
            issue(
                language,
                "S6422",
                format!(
                    "Replace this use of 'Task.{member}' with 'await'. Do not perform blocking operations in Azure Functions."
                ),
                range_of(call, source),
            )
        })
        .collect()
}

/// Blocking member accesses and calls nested inside `scope`.
fn blocking_calls_in_scope<'t>(scope: Node<'t>, source: &str) -> Vec<Node<'t>> {
    let accesses = collect_kinds(scope, &["member_access_expression"])
        .into_iter()
        .filter(|access| !is_error_tainted(*access))
        .filter(|access| {
            matches!(
                expression_name(*access, source).unwrap_or(""),
                "Result" | "Wait"
            )
        });
    let get_results = collect_kinds(scope, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| callee_name(*invocation, source) == Some("GetResult"));
    accesses.chain(get_results).collect()
}
