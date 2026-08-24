use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::{callee_name, first_named_child, invocation_arguments};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3216 — `ConfigureAwait(true)` is the default and only adds
/// noise; capture the context deliberately with `false`.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter(|invocation| callee_name(*invocation, source) == Some("ConfigureAwait"))
        .filter(|invocation| {
            invocation_arguments(*invocation).iter().any(|argument| {
                first_named_child(*argument).is_some_and(|value| node_text(value, source) == "true")
            })
        })
        .map(|invocation| {
            issue(
                language,
                "S3216",
                "Pass 'false' to 'ConfigureAwait'.",
                range_of(invocation),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3216_counts_only_the_true_configures() {
        let report = analyze_default(
            "class C\n{\n    async System.Threading.Tasks.Task Run(Task task)\n    {\n        await task.ConfigureAwait(true);\n        await task.ConfigureAwait(false);\n        await task.ConfigureAwait(true);\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S3216").len(), 2);
    }
}
