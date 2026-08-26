use crate::CsLanguage;
use crate::cst::{is_error_tainted, issue, range_of};
use crate::rules::literals::{literal_inner_text, string_literals};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5332 — clear-text channels expose everything they carry;
/// namespace schemas and loopback addresses are exempt.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const EXEMPT_MARKERS: [&str; 4] = ["://localhost", "127.0.0.1", "www.w3.org", "schemas."];
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let lowered = literal_inner_text(literal, source).to_ascii_lowercase();
        let clear_text = (lowered.contains("http://") || lowered.contains("ws://"))
            && !EXEMPT_MARKERS.iter().any(|marker| lowered.contains(marker));
        if clear_text {
            issues.push(issue(
                language,
                "S5332",
                "Serve this connection over an encrypted channel instead.",
                range_of(literal, source),
            ));
        }
    }
    issues
}
