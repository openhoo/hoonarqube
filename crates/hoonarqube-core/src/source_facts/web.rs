//! Lexical facts for the opt-in Community 26.11 Web duplication measurement.
//! Identifiers, tags, assignments and template expressions retain their exact
//! spelling. Comments and ASCII spacing do not contribute clone tokens.
use super::{
    Language, MAX_FACT_TOKENS, MAX_SOURCE_BYTES, MAX_SOURCE_LINES, NormalizedToken, SourceFacts,
    fallback_metrics,
};
use std::collections::HashMap;

fn word(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}
fn lex(input: &[u8]) -> Result<(usize, bool), String> {
    let first = input[0];
    if first.is_ascii_whitespace() {
        return Ok((
            input.iter().take_while(|b| b.is_ascii_whitespace()).count(),
            false,
        ));
    }
    if input.starts_with(b"//") {
        return Ok((
            input
                .iter()
                .position(|b| matches!(b, b'\r' | b'\n'))
                .unwrap_or(input.len()),
            false,
        ));
    }
    for (start, end, token) in [
        (b"<!--".as_slice(), b"-->".as_slice(), false),
        (b"<%--", b"%>", false),
        (b"{#", b"#}", false),
        (b"/*", b"*/", false),
        (b"<%", b"%>", true),
    ] {
        if input.starts_with(start) {
            let n = input[start.len()..]
                .windows(end.len())
                .position(|p| p == end)
                .ok_or("unclosed Web comment or expression")?;
            return Ok((start.len() + n + end.len(), token));
        }
    }
    if input.starts_with(b"<!DOCTYPE") {
        let line = &input[..input
            .iter()
            .position(|b| matches!(b, b'\r' | b'\n'))
            .unwrap_or(input.len())];
        if let Some(i) = line.iter().rposition(|b| *b == b'>') {
            return Ok((i + 1, true));
        }
        return Err("unterminated Web doctype".into());
    }
    if first == b'<' {
        let from = if input.get(1) == Some(&b'/') { 2 } else { 1 };
        let n = input[from..]
            .iter()
            .take_while(|b| word(**b) || **b == b':')
            .count();
        if n > 0 {
            let end = from + n;
            return Ok((end + usize::from(input.get(end) == Some(&b'>')), true));
        }
    }
    if input.starts_with(b"/>") {
        return Ok((2, true));
    }
    if first == b'=' {
        if matches!(input.get(1), Some(b'\'' | b'"')) {
            let end = input[2..]
                .iter()
                .position(|b| matches!(b, b'\'' | b'"'))
                .ok_or("unclosed quoted Web assignment")?;
            return Ok((end + 3, true));
        }
        let n = input[1..]
            .iter()
            .take_while(|b| {
                !b.is_ascii_whitespace() && !matches!(b, b'\'' | b'"' | b'=' | b'<' | b'>' | b'`')
            })
            .count();
        if n > 0 {
            return Ok((1 + n, true));
        }
    }
    if word(first) {
        return Ok((input.iter().take_while(|b| word(**b)).count(), true));
    }
    Ok((1, true))
}

/// Returns bounded Web tokens and physical file lines. Non-ASCII or malformed
/// inputs outside the measured contract remain unavailable rather than zero.
///
/// # Errors
/// Returns an error for unqualified syntax or encoding, or excessive input, lines or tokens.
pub fn community_web_facts(source: &str, remaining_tokens: usize) -> Result<SourceFacts, String> {
    if source.len() > MAX_SOURCE_BYTES || !source.is_ascii() || source.contains('\0') {
        return Err("Web duplication requires bounded ASCII text".into());
    }
    let b = source.as_bytes();
    let mut tokens = Vec::new();
    let mut symbols = Vec::new();
    let mut ids = HashMap::new();
    let (mut pos, mut line) = (0usize, 1u32);
    while pos < b.len() {
        let (len, emit) = lex(&b[pos..])?;
        let end = pos + len;
        let first = line;
        let mut last = line;
        for i in pos..end {
            last = line;
            if b[i] == b'\r' || (b[i] == b'\n' && (i == 0 || b[i - 1] != b'\r')) {
                line += 1;
            }
        }
        if line as usize > MAX_SOURCE_LINES {
            return Err("Web line budget exceeded".into());
        }
        if emit {
            if tokens.len() >= remaining_tokens.min(MAX_FACT_TOKENS) {
                return Err("Web token budget exceeded".into());
            }
            let key = &source[pos..end];
            let id = u32::try_from(symbols.len()).map_err(|_| "Web symbol budget exceeded")?;
            let symbol = *ids.entry(key).or_insert_with(|| {
                symbols.push(key.to_owned());
                id
            });
            tokens.push(NormalizedToken {
                symbol,
                start_line: first,
                end_line: last,
                start_byte: u32::try_from(pos).map_err(|_| "Web byte budget exceeded")?,
                end_byte: u32::try_from(end).map_err(|_| "Web byte budget exceeded")?,
            });
        }
        pos = end;
    }
    let mut metrics = fallback_metrics(source, Language::Html);
    metrics.lines = line;
    Ok(SourceFacts {
        metrics,
        tokens,
        symbols,
        units: Vec::new(),
        error: None,
        language: Language::Html,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn comments_do_not_count_but_template_tokens_keep_spelling_and_positions() {
        let source = "<p id='a'>\r\n<!--x\n y -->\n<%= value %></p>\n";
        let f = community_web_facts(source, 30).unwrap();
        let images: Vec<_> = f
            .tokens
            .iter()
            .map(|t| {
                (
                    f.symbols[t.symbol as usize].as_str(),
                    t.start_line,
                    t.end_line,
                )
            })
            .collect();
        assert_eq!(
            images,
            [
                ("<p", 1, 1),
                ("id", 1, 1),
                ("='a'", 1, 1),
                (">", 1, 1),
                ("<%= value %>", 4, 4),
                ("</p>", 4, 4)
            ]
        );
        assert_eq!(f.metrics.lines, 5);
    }

    #[test]
    fn excessive_or_ambiguous_input_is_not_a_zero_token_measurement() {
        for input in ["<!--", "<%", "<!DOCTYPE", "='", "x\0", "é"] {
            assert!(community_web_facts(input, 20).is_err(), "{input:?}");
        }
        assert!(community_web_facts("one two", 1).is_err());
        assert_eq!(community_web_facts("one two", 2).unwrap().tokens.len(), 2);
    }
}
