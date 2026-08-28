use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_from_byte_offsets};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S818 — numeric literal suffixes are uppercase.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["integer_literal", "real_literal"])
        .into_iter()
        .filter(|literal| !is_error_tainted(*literal))
        .filter_map(|literal| {
            lowercase_long_suffix_offset(node_text(literal, source)).map(|offset| (literal, offset))
        })
        .map(|(literal, offset)| {
            let start = literal.start_byte() + offset;
            issue(
                language,
                "S818",
                "Upper case this literal suffix.",
                range_from_byte_offsets(start, start + 1, source),
            )
        })
        .collect()
}

/// Splits the numeric body from the suffix by scanning forward from the
/// radix prefix, so hex digits `d`/`D`/`f` are never mistaken for suffix
/// letters and digit separators stay inside the body. Any lowercase ASCII
/// letter behind the body is a lowercase suffix.
fn lowercase_long_suffix_offset(text: &str) -> Option<usize> {
    if text.is_empty() {
        return None;
    }
    let radix = match text.as_bytes().get(1) {
        Some(b'x' | b'X') => Some(true),
        Some(b'b' | b'B') => Some(false),
        _ => None,
    };
    let body = &text[if radix.is_some() { 2 } else { 0 }..];
    let body_end = body
        .char_indices()
        .take_while(|(_, char)| match radix {
            Some(true) => char.is_ascii_hexdigit() || *char == '_',
            _ => char.is_ascii_digit() || matches!(char, '.' | '_' | 'e' | 'E' | '+' | '-'),
        })
        .map(|(index, char)| index + char.len_utf8())
        .last()
        .unwrap_or(0);
    body[body_end..]
        .char_indices()
        .find_map(|(offset, character)| (character == 'l').then_some(body_end + offset))
}
