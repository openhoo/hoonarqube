use super::support::literal_inner_text;
use super::support::string_literals;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2479 — raw whitespace/control characters inside literals
/// hide their intent; spell them as escape sequences.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    string_literals(root)
        .into_iter()
        .filter(|literal| {
            literal_inner_text(*literal, source)
                .chars()
                .any(char::is_control)
        })
        .map(|literal| {
            issue(
                language,
                "S2479",
                "Replace this control character with its escape sequence form.",
                range_of(literal),
            )
        })
        .collect()
}
