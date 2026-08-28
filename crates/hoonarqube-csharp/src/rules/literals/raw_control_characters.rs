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
        .filter_map(|literal| {
            let (index, character) = literal_inner_text(literal, source)
                .chars()
                .enumerate()
                .find(|(_, character)| character.is_control())?;
            Some(issue(
                language,
                "S2479",
                format!(
                    "Replace the control character at position {} by its escape sequence '\\u{:04X}'.",
                    index + 1,
                    u32::from(character)
                ),
                range_of(literal, source),
            ))
        })
        .collect()
}
