use crate::CsLanguage;
use crate::cst::{is_error_tainted, issue, range_of};
use crate::rules::literals::{literal_inner_text, string_literals};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S7039 — 'unsafe-inline' or 'unsafe-eval' sources hollow out
/// the Content-Security-Policy.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const UNSAFE_CSP_SOURCES: [&str; 2] = ["unsafe-inline", "unsafe-eval"];
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let lowered = literal_inner_text(literal, source).to_ascii_lowercase();
        let permissive = lowered.contains("content-security-policy")
            && UNSAFE_CSP_SOURCES
                .iter()
                .any(|source_token| lowered.contains(source_token));
        if permissive {
            issues.push(issue(
                language,
                "S7039",
                "Serve a restrictive Content-Security-Policy.",
                range_of(literal, source),
            ));
        }
    }
    issues
}
