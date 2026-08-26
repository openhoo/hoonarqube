use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S818 — numeric literal suffixes are uppercase.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["integer_literal", "real_literal"])
        .into_iter()
        .filter(|literal| !is_error_tainted(*literal))
        .filter(|literal| has_lowercase_suffix(node_text(*literal, source)))
        .map(|literal| {
            issue(
                language,
                "S818",
                "Uppercase this numeric literal suffix.",
                range_of(literal),
            )
        })
        .collect()
}

/// Longest trailing run of suffix letters whose remainder still ends in a
/// digit yields the literal's suffix; lowercase suffixes are flagged. Hex
/// digits outside the suffix set fall out naturally (`0xd` stays clean).
fn has_lowercase_suffix(text: &str) -> bool {
    const SUFFIX_LETTERS: [char; 10] = ['u', 'U', 'l', 'L', 'f', 'F', 'd', 'D', 'm', 'M'];
    if text.is_empty() {
        return false;
    }
    let run_len = text
        .chars()
        .rev()
        .take_while(|letter| SUFFIX_LETTERS.contains(letter))
        .count();
    for k in 0..=run_len.min(text.len() - 1) {
        if text.as_bytes()[text.len() - k - 1].is_ascii_digit() {
            return text[text.len() - k..]
                .chars()
                .any(|letter: char| letter.is_ascii_lowercase());
        }
    }
    false
}
