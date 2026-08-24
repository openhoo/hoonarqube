use super::support::literal_assignments;
use super::support::literal_inner_text;
use crate::cst::{issue, range_of};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6418 — names matching a secret word plus high-entropy
/// literal values point at hard-coded secrets.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    literal_assignments(root, source)
        .into_iter()
        .filter(|(_, name, literal)| {
            secret_word_in(name, &options.secret_words).is_some()
                && looks_like_secret(
                    literal_inner_text(*literal, source),
                    options.secret_randomness_sensibility,
                )
        })
        .map(|(anchor, _, _)| {
            issue(
                language,
                "S6418",
                "Review this potentially hard-coded secret.",
                range_of(anchor),
            )
        })
        .collect()
}

/// Matches the catalog default `secretWords` shapes natively
/// (`api[_\-]?key`) and degrades every other entry to a case-insensitive
/// substring search.
fn secret_word_in<'w>(name: &str, words: &'w [String]) -> Option<&'w str> {
    let lowered = name.to_lowercase();
    words.iter().map(String::as_str).find(|word| {
        if word.eq_ignore_ascii_case(r"api[_\-]?key") {
            lowered.contains("apikey") || lowered.contains("api_key") || lowered.contains("api-key")
        } else {
            lowered.contains(&word.to_lowercase())
        }
    })
}

/// Entropy heuristic: enough distinct character classes and a non-trivial
/// length separate real secrets from placeholder values like `"token"`.
fn looks_like_secret(value: &str, sensibility: u32) -> bool {
    let classes = [
        value.chars().any(|c| c.is_ascii_lowercase()),
        value.chars().any(|c| c.is_ascii_uppercase()),
        value.chars().any(|c| c.is_ascii_digit()),
        value.chars().any(|c| !c.is_ascii_alphanumeric()),
    ];
    value.len() >= 8
        && classes.iter().filter(|seen| **seen).count()
            >= usize::try_from(sensibility).unwrap_or(usize::MAX)
}
