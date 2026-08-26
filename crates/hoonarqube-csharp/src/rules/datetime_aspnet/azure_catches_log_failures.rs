use super::support::azure_function_classes;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6423 — swallowed failures in a Function vanish from view;
/// every catch must log.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const LOGGING_MARKERS: [&str; 3] = ["Log", "_log", "logger"];
    azure_function_classes(root, source)
        .iter()
        .flat_map(|class_node| collect_kinds(*class_node, &["catch_clause"]))
        .filter(|catch_clause| !is_error_tainted(*catch_clause))
        .filter(|catch_clause| {
            let text = node_text(*catch_clause, source);
            !LOGGING_MARKERS.iter().any(|marker| text.contains(marker))
        })
        .map(|catch_clause| {
            issue(
                language,
                "S6423",
                "Log the failure inside this catch block.",
                range_of(catch_clause, source),
            )
        })
        .collect()
}
