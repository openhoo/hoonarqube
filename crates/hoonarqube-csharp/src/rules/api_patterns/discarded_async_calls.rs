use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::expressions::callee_name;
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
            let inside_async = ancestors_of(invocation)
                .find(|ancestor| ancestor.kind() == "method_declaration")
                .is_some_and(|method| crate::cst::modifiers_of(method, source).contains(&"async"));
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
