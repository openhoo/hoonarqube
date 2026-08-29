use crate::CsLanguage;
use crate::cst::{issue, range_from_byte_offsets};
use hoonarqube_ir::Issue;

/// csharpsquid:S2757 — `= +` is two operators where one was meant.
pub(crate) fn check(source: &str, language: CsLanguage) -> Vec<Issue> {
    transposed_assignments(source)
        .into_iter()
        .map(|(offset, sign)| {
            issue(
                language,
                "S2757",
                format!("Was '{sign}=' meant instead?"),
                range_from_byte_offsets(offset + 1, offset + 2, source),
            )
        })
        .collect()
}

#[derive(Clone, Copy)]
enum LexicalState {
    Code,
    LineComment,
    BlockComment,
    String,
    VerbatimString,
    RawString(usize),
    Character,
}

/// Byte offsets and signs of adjacent `=+` / `=-` pairs in code. Comments
/// and every C# string form are skipped without losing multiline state.
fn transposed_assignments(source: &str) -> Vec<(usize, char)> {
    let bytes = source.as_bytes();
    let mut matches = Vec::new();
    let mut state = LexicalState::Code;
    let mut index = 0_usize;
    while index < bytes.len() {
        let (next_state, next_index, found) = scan_state(state, bytes, index);
        if let Some(found) = found {
            matches.push(found);
        }
        state = next_state;
        index = next_index;
    }
    matches
}

fn scan_state(
    state: LexicalState,
    bytes: &[u8],
    index: usize,
) -> (LexicalState, usize, Option<(usize, char)>) {
    match state {
        LexicalState::Code => scan_code(bytes, index),
        LexicalState::LineComment => scan_line_comment(bytes, index),
        LexicalState::BlockComment => scan_block_comment(bytes, index),
        LexicalState::String => scan_quoted(bytes, index, b'"', LexicalState::String),
        LexicalState::Character => scan_quoted(bytes, index, b'\'', LexicalState::Character),
        LexicalState::VerbatimString => scan_verbatim_string(bytes, index),
        LexicalState::RawString(delimiter_len) => scan_raw_string(bytes, index, delimiter_len),
    }
}

fn scan_code(bytes: &[u8], index: usize) -> (LexicalState, usize, Option<(usize, char)>) {
    if starts_with(bytes, index, b"//") {
        return (LexicalState::LineComment, index + 2, None);
    }
    if starts_with(bytes, index, b"/*") {
        return (LexicalState::BlockComment, index + 2, None);
    }
    if bytes[index] == b'"' {
        return begin_string(bytes, index);
    }
    if bytes[index] == b'\'' {
        return (LexicalState::Character, index + 1, None);
    }
    let sign = bytes.get(index + 1).copied();
    if bytes[index] == b'='
        && matches!(sign, Some(b'+' | b'-'))
        && index > 0
        && !is_operator_byte(bytes[index - 1])
    {
        return (
            LexicalState::Code,
            index + 2,
            sign.map(|sign| (index, char::from(sign))),
        );
    }
    (LexicalState::Code, index + 1, None)
}

fn begin_string(bytes: &[u8], index: usize) -> (LexicalState, usize, Option<(usize, char)>) {
    let quote_count = repeated_byte_count(bytes, index, b'"');
    if quote_count >= 3 {
        return (
            LexicalState::RawString(quote_count),
            index + quote_count,
            None,
        );
    }
    let state = if is_verbatim_string_prefix(bytes, index) {
        LexicalState::VerbatimString
    } else {
        LexicalState::String
    };
    (state, index + 1, None)
}

fn scan_line_comment(bytes: &[u8], index: usize) -> (LexicalState, usize, Option<(usize, char)>) {
    let state = if bytes[index] == b'\n' {
        LexicalState::Code
    } else {
        LexicalState::LineComment
    };
    (state, index + 1, None)
}

fn scan_block_comment(bytes: &[u8], index: usize) -> (LexicalState, usize, Option<(usize, char)>) {
    if starts_with(bytes, index, b"*/") {
        (LexicalState::Code, index + 2, None)
    } else {
        (LexicalState::BlockComment, index + 1, None)
    }
}

fn scan_quoted(
    bytes: &[u8],
    index: usize,
    delimiter: u8,
    state: LexicalState,
) -> (LexicalState, usize, Option<(usize, char)>) {
    if bytes[index] == b'\\' {
        return (state, (index + 2).min(bytes.len()), None);
    }
    if bytes[index] == delimiter || bytes[index] == b'\n' {
        return (LexicalState::Code, index + 1, None);
    }
    (state, index + 1, None)
}

fn scan_verbatim_string(
    bytes: &[u8],
    index: usize,
) -> (LexicalState, usize, Option<(usize, char)>) {
    if starts_with(bytes, index, b"\"\"") {
        return (LexicalState::VerbatimString, index + 2, None);
    }
    if bytes[index] == b'"' {
        return (LexicalState::Code, index + 1, None);
    }
    (LexicalState::VerbatimString, index + 1, None)
}

fn scan_raw_string(
    bytes: &[u8],
    index: usize,
    delimiter_len: usize,
) -> (LexicalState, usize, Option<(usize, char)>) {
    let quote_count = repeated_byte_count(bytes, index, b'"');
    if quote_count >= delimiter_len {
        (LexicalState::Code, index + delimiter_len, None)
    } else {
        (
            LexicalState::RawString(delimiter_len),
            index + quote_count.max(1),
            None,
        )
    }
}

fn starts_with(bytes: &[u8], index: usize, needle: &[u8]) -> bool {
    bytes.get(index..index.saturating_add(needle.len())) == Some(needle)
}

fn repeated_byte_count(bytes: &[u8], index: usize, needle: u8) -> usize {
    bytes[index..]
        .iter()
        .take_while(|byte| **byte == needle)
        .count()
}

fn is_verbatim_string_prefix(bytes: &[u8], quote_index: usize) -> bool {
    bytes.get(quote_index.wrapping_sub(1)) == Some(&b'@')
        || (bytes.get(quote_index.wrapping_sub(2)) == Some(&b'@')
            && bytes.get(quote_index.wrapping_sub(1)) == Some(&b'$'))
}

fn is_operator_byte(byte: u8) -> bool {
    matches!(
        byte,
        b'=' | b'+' | b'-' | b'*' | b'/' | b'%' | b'<' | b'>' | b'!' | b'|' | b'&' | b'^' | b'?'
    )
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2757_flags_each_transposed_line_and_counts_them() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        total =+ amount;\n        count =+ step;\n        Log(total);\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2757");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s2757_ignores_spaced_unary_plus_and_operator_pairs() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        total = +amount;\n        if (a ==+ b) { }\n        value ??=+ fallback;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2757").is_empty());
    }

    #[test]
    fn s2757_ignores_literals_and_comments_but_scans_resumed_code() {
        let report = analyze_default(
            "class A\n{\n    void M()\n    {\n        var regular = \"x =+ y\"; // z =- y\n        var verbatim = @\"x =+ \"\" y\";\n        var raw = \"\"\"x =- y\"\"\";\n        var character = '='; /* x =+ y\n        still commented =- y */ total =+ amount; count =- step;\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2757");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 9);
        assert_eq!(flagged[1].range.start.line, 9);
    }

    #[test]
    fn s2757_reports_each_pair_with_character_columns() {
        let report =
            analyze_default("class A\n{\n    void M() { café =+ one; other =- two; }\n}\n");
        let flagged = with_key(&report, "csharpsquid:S2757");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.column, 21);
        assert_eq!(flagged[1].range.start.column, 35);
    }
}
