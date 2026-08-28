use super::support::literal_inner_text;
use super::support::string_literals;
use crate::cst::{issue, range_of};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1192 — string literals repeated up to the configured
/// threshold deserve a named constant. The first occurrence anchors the one
/// issue for that repeated value; the empty literal is exempt.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut counts: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    for literal in string_literals(root) {
        let text = literal_inner_text(literal, source);
        if !text.is_empty() {
            *counts.entry(text).or_insert(0) += 1;
        }
    }
    let threshold = options.duplicate_string_threshold.max(2);
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        let text = literal_inner_text(literal, source);
        if text.is_empty() || counts[text] < threshold {
            continue;
        }
        if !seen.insert(text) {
            continue;
        }
        issue_text(
            &mut issues,
            language,
            text,
            counts[text],
            range_of(literal, source),
        );
    }
    issues
}

/// One S1192 finding for a repeated literal, anchored on its first occurrence.
fn issue_text(
    issues: &mut Vec<Issue>,
    language: CsLanguage,
    text: &str,
    count: u32,
    range: hoonarqube_ir::Range,
) {
    issues.push(issue(
        language,
        "S1192",
        format!("Define a constant instead of using this literal '{text}' {count} times."),
        range,
    ));
}
