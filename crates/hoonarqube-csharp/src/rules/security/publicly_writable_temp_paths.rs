use crate::CsLanguage;
use crate::cst::{is_error_tainted, issue, range_of};
use crate::rules::literals::{literal_inner_text, string_literals};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5443 — publicly writable directories let any local user swap
/// the files you just wrote.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const PUBLIC_TEMP_MARKERS: [&str; 4] = ["/tmp/", "/var/tmp", "%temp%", "\\windows\\temp"];
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        if is_error_tainted(literal) {
            continue;
        }
        let lowered = literal_inner_text(literal, source).to_ascii_lowercase();
        if PUBLIC_TEMP_MARKERS
            .iter()
            .any(|marker| lowered.contains(marker))
        {
            issues.push(issue(
                language,
                "S5443",
                "Make sure publicly writable directories are used safely here.",
                range_of(literal, source),
            ));
        }
    }
    issues
}
