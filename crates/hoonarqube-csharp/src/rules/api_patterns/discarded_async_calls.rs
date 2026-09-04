use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::{callee_name, enclosing_callable};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6966 — use an available awaitable API from async methods.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| !is_error_tainted(*invocation))
        .filter_map(|invocation| {
            let async_alternative = match callee_name(invocation, source)? {
                "Read" => "ReadAsync",
                "ReadAllLines" => "ReadAllLinesAsync",
                "ToList" => "ToListAsync",
                "FirstOrDefault" => "FirstOrDefaultAsync",
                _ => return None,
            };
            let inside_async = enclosing_callable(invocation).is_some_and(|callable| {
                crate::cst::modifiers_of(callable, source).contains(&"async")
            });
            inside_async.then_some((invocation, async_alternative))
        })
        .map(|(invocation, async_alternative)| {
            issue(
                language,
                "S6966",
                format!("Await {async_alternative} instead."),
                range_of(invocation, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6966_isolated_to_nearest_local_function_async_context() {
        let async_local = analyze_default(
            "class C\n{\n    void Outer(List<int> items)\n    {\n        async Task Local()\n        {\n            items.ToList();\n        }\n    }\n}\n",
        );
        let flagged = with_key(&async_local, "csharpsquid:S6966");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 7);
        assert_eq!(flagged[0].range.start.column, 12);
        assert_eq!(flagged[0].message, "Await ToListAsync instead.");

        let sync_local = analyze_default(
            "class C\n{\n    async Task Outer(List<int> items)\n    {\n        void Local()\n        {\n            items.ToList();\n        }\n    }\n}\n",
        );
        assert!(with_key(&sync_local, "csharpsquid:S6966").is_empty());
    }
}
