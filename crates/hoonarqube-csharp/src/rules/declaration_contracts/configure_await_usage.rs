use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::first_named_child;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3216 — awaited calls in library code should opt out of
/// synchronization-context capture.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["await_expression"])
        .into_iter()
        .filter(|await_expression| !is_error_tainted(*await_expression))
        .filter_map(first_named_child)
        .filter(|awaited| !node_text(*awaited, source).contains("ConfigureAwait(false)"))
        .map(|awaited| {
            issue(
                language,
                "S3216",
                "Add '.ConfigureAwait(false)' to this call to allow execution to continue in any thread.",
                range_of(awaited, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s3216_flags_awaited_calls_without_configure_await_false() {
        let report = analyze_default(
            "class C\n{\n    async Task Run(Task task)\n    {\n        await task;\n        await task.ConfigureAwait(false);\n    }\n}\n",
        );
        let found = with_key(&report, "csharpsquid:S3216");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 5);
        assert_eq!(
            found[0].message,
            "Add '.ConfigureAwait(false)' to this call to allow execution to continue in any thread."
        );
    }
}
