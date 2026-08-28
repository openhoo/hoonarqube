use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::callee_name;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6575 — pass the original timezone identifier directly to
/// `TimeZoneInfo` instead of converting it first.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for invocation in collect_kinds(root, &["invocation_expression"])
        .into_iter()
        .filter(|invocation| {
            !is_error_tainted(*invocation)
                && callee_name(*invocation, source) == Some("FindSystemTimeZoneById")
        })
    {
        let converted = ancestors_of(invocation)
            .find(|ancestor| ancestor.kind() == "method_declaration")
            .and_then(|method| {
                collect_kinds(method, &["variable_declarator"])
                    .into_iter()
                    .filter(|declarator| node_text(*declarator, source).contains("TZConvert."))
                    .flat_map(|declarator| collect_kinds(declarator, &["invocation_expression"]))
                    .find(|converter| {
                        matches!(
                            callee_name(*converter, source),
                            Some("IanaToWindows" | "WindowsToIana")
                        )
                    })
            });
        if let Some(converter) = converted {
            let anchor = collect_kinds(converter, &["identifier"])
                .into_iter()
                .last()
                .unwrap_or(converter);
            issues.push(issue(
                language,
                "S6575",
                "Use \"TimeZoneInfo.FindSystemTimeZoneById\" directly instead of \"TZConvert.IanaToWindows\"",
                range_of(anchor, source),
            ));
        }
    }
    issues
}
