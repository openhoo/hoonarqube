use super::support::azure_function_methods;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::expressions::invocation_function;
use crate::rules::structure::body_of;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6423 — swallowed failures in a Function vanish from view;
/// every catch must log.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const LOGGING_MARKERS: [&str; 3] = ["Log", "_log", "logger"];
    azure_function_methods(root, source)
        .into_iter()
        .filter_map(body_of)
        .flat_map(|body| collect_kinds(body, &["catch_clause"]))
        .filter(|catch_clause| !is_error_tainted(*catch_clause))
        .filter(|catch_clause| {
            !collect_kinds(*catch_clause, &["invocation_expression"])
                .into_iter()
                .filter_map(invocation_function)
                .map(|function| node_text(function, source))
                .any(|function| {
                    LOGGING_MARKERS
                        .iter()
                        .any(|marker| function.contains(marker))
                })
        })
        .map(|catch_clause| {
            let mut cursor = catch_clause.walk();
            let anchor = catch_clause
                .children(&mut cursor)
                .find(|child| child.kind() == "catch")
                .unwrap_or(catch_clause);
            issue(
                language,
                "S6423",
                "Log exception via ILogger with LogLevel Information, Warning, Error, or Critical.",
                range_of(anchor, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6423_ignores_non_function_helpers_in_function_classes() {
        let report = analyze_default(
            "class Fn\n{\n    [FunctionName(\"Run\")]\n    public void Run() { try { Work(); } catch (Exception ex) { _log.Error(ex); } }\n\n    public void Helper()\n    {\n        try { Work(); } catch (Exception) { throw; }\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6423").is_empty());
    }

    #[test]
    fn s6423_does_not_treat_logging_words_as_logging_calls() {
        let report = analyze_default(
            "class Fn\n{\n    [FunctionName(\"Run\")]\n    public void Run()\n    {\n        try { Work(); } catch (Exception) { var loggerMessage = \"failed\"; }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6423").len(), 1);
    }
}
