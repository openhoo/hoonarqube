use super::support::literal_assignments;
use super::support::literal_inner_text;
use crate::cst::{issue, range_of};
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2068 — names carrying a credential word must not receive
/// hard-coded string literals.
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    literal_assignments(root, source)
        .into_iter()
        .filter(|(_, name, literal)| {
            !literal_inner_text(*literal, source).is_empty()
                && credential_word_in(name, &options.credential_words).is_some()
        })
        .map(|(anchor, name, _)| {
            issue(
                language,
                "S2068",
                format!("Review this hard-coded credential assigned through '{name}'."),
                range_of(anchor, source),
            )
        })
        .collect()
}

/// Case-insensitive substring search for a credential word inside a name.
fn credential_word_in<'w>(name: &str, words: &'w [String]) -> Option<&'w str> {
    let lowered = name.to_lowercase();
    words
        .iter()
        .map(String::as_str)
        .find(|word| lowered.contains(&word.to_lowercase()))
}
