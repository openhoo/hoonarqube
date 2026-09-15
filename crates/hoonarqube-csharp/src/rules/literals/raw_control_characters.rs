use super::support::{literal_inner_text, string_literals};
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2479 — control characters that cannot spell themselves hide
/// their intent and must be written as escape sequences. The reference only
/// inspects literals whose syntax supports escape sequences: verbatim, raw,
/// and interpolated-verbatim strings are "inescapable" by design, so their
/// physical line breaks and tabs are the literal's spelling, never findings.
/// Within a checkable plain literal the first character of the reference's
/// table (C0 controls, DEL, and zero-width/formatting spaces) is reported,
/// one finding per literal. Interpolated text parts carry no static content
/// here and stay skipped.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    string_literals(root)
        .into_iter()
        .filter(|literal| literal.kind() == "string_literal")
        .filter_map(|literal| {
            let (index, name) = literal_inner_text(literal, source)
                .char_indices()
                .find_map(|(index, character)| escape_name(character).map(|name| (index, name)))?;
            Some(issue(
                language,
                "S2479",
                format!(
                    "Replace the control character at position {} by its escape sequence '{}'.",
                    index + 1,
                    name,
                ),
                range_of(literal, source),
            ))
        })
        .collect()
}

/// Reference escape spelling of a tracked character: `None` when the
/// character may appear literally in a plain string literal.
fn escape_name(character: char) -> Option<String> {
    match character {
        '\u{0000}' => Some("\\0".into()),
        '\u{0007}' => Some("\\a".into()),
        '\u{0008}' => Some("\\b".into()),
        '\u{0009}' => Some("\\t".into()),
        '\u{000A}' => Some("\\n".into()),
        '\u{000B}' => Some("\\v".into()),
        '\u{000C}' => Some("\\f".into()),
        '\u{000D}' => Some("\\r".into()),
        tracked => tracked_control(tracked).then(|| format!("\\u{:04X}", u32::from(tracked))),
    }
}

/// Characters without a short escape: the remaining C0 controls, DEL, and
/// the reference's zero-width and formatting spaces.
fn tracked_control(character: char) -> bool {
    let code = u32::from(character);
    code < 0x20
        || code == 0x7F
        || matches!(
            code,
            0x1680 | 0x2000..=0x200D | 0x2028 | 0x2029 | 0x202F | 0x205F | 0x2060 | 0x3000 | 0xFEFF
        )
}
