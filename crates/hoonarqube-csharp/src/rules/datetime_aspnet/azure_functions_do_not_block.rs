use super::support::azure_function_methods;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, expression_name};
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6422 — blocking on async work inside a Function deadlocks
/// the single-invocation host.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    azure_function_methods(root, source)
        .into_iter()
        .filter_map(body_of)
        .flat_map(|body| blocking_calls_in_scope(body, source))
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

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6422_ignores_non_function_helpers_in_function_classes() {
        let report = analyze_default(
            "class Fn\n{\n    [FunctionName(\"Run\")]\n    public async Task Run() { await Work(); }\n\n    public int Helper()\n    {\n        var task = Task.Run(() => 1);\n        return task.Result;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6422").is_empty());
    }
}
