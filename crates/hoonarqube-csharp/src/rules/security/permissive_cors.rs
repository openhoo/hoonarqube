use super::support::identifier_usages;
use crate::CsLanguage;
use crate::cst::{is_error_tainted, issue, range_of};
use crate::rules::literals::{literal_inner_text, string_literals};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5122 — reflecting any origin erases the same-origin
/// protection CORS exists to provide.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const ANY_ORIGIN_MARKERS: [&str; 1] = ["AllowAnyOrigin"];
    let mut issues: Vec<Issue> = identifier_usages(root, source, &ANY_ORIGIN_MARKERS)
        .into_iter()
        .map(|identifier| {
            issue(
                language,
                "S5122",
                "Restrict CORS responses to trusted origins.",
                range_of(identifier),
            )
        })
        .collect();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let lowered = literal_inner_text(literal, source).to_ascii_lowercase();
        if lowered.contains("access-control-allow-origin") && lowered.contains('*') {
            issues.push(issue(
                language,
                "S5122",
                "Restrict CORS responses to trusted origins.",
                range_of(literal),
            ));
        }
    }
    issues
}
