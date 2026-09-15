use super::support::literal_inner_text;
use super::support::string_literals;
use crate::cst::{ancestors_of, issue, range_of};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// The reference rule never reports literals shorter than five characters.
const MIN_DUPLICATED_LENGTH: usize = 5;

/// csharpsquid:S1192 — string literals repeated up to the configured
/// threshold deserve a named constant. The first occurrence anchors the one
/// issue for that repeated value; the empty literal is exempt, as is every
/// literal below the reference rule's five-character floor.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut counts: std::collections::HashMap<&str, u32> = std::collections::HashMap::new();
    for literal in string_literals(root) {
        let text = literal_inner_text(literal, source);
        if !text.is_empty() && !inside_attribute_list(literal) {
            *counts.entry(text).or_insert(0) += 1;
        }
    }
    let threshold = options.duplicate_string_threshold.max(2);
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    let mut issues = Vec::new();
    for literal in string_literals(root) {
        let text = literal_inner_text(literal, source);
        if text.is_empty()
            || text.chars().count() < MIN_DUPLICATED_LENGTH
            || inside_attribute_list(literal)
            || counts[text] < threshold
        {
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

/// The reference rule never descends into attribute lists: attribute
/// arguments are metadata identities, not duplicated content to extract.
fn inside_attribute_list(literal: Node<'_>) -> bool {
    ancestors_of(literal).any(|ancestor| ancestor.kind() == "attribute_list")
}
