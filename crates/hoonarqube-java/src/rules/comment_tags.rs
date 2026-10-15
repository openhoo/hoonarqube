//! `java:S1134` and `java:S1135`: comment tags with the Java 8.41 reference's
//! first-occurrence letter boundaries and one finding per trivia/physical line.

use std::sync::LazyLock;

use crate::support::{LineIndex, node_text, walk_all};
use hoonarqube_ir::{Issue, Pos, Range, u32_saturating};
use regex::Regex;
use tree_sitter::Node;

static TODO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i-u:TODO)").expect("constant TODO pattern"));
// Java's case-insensitive String matching also equates I with dotted/dotless I.
static FIXME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i-u:F)[Iiıİ](?i-u:XME)").expect("constant FIXME pattern"));
static LETTER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^\p{L}$").expect("constant Unicode letter pattern"));

pub(crate) fn check(root: Node<'_>, source: &str, lines: &LineIndex) -> Vec<Issue> {
    let ranges = whole_line_ranges(source);
    let mut issues = Vec::new();
    walk_all(root, &mut |node| {
        if !matches!(node.kind(), "line_comment" | "block_comment") {
            return;
        }
        let mut offset = node.start_byte();
        for line in node_text(node, source).split(['\r', '\n']) {
            for (pattern, key, message) in [
                (
                    &*TODO,
                    "java:S1135",
                    "Complete the task associated to this TODO comment.",
                ),
                (
                    &*FIXME,
                    "java:S1134",
                    "Take the required action to fix the issue indicated by this comment.",
                ),
            ] {
                if has_tag(line, pattern) {
                    let index = lines.position(source, offset).line.saturating_sub(1) as usize;
                    if let Some(range) = ranges.get(index) {
                        issues.push(Issue::new(key, message, range.clone()));
                    }
                }
            }
            // Both separators occupy one byte; the empty CRLF fragment has no tag.
            offset += line.len() + 1;
        }
    });
    issues
}

fn has_tag(line: &str, pattern: &Regex) -> bool {
    let Some(tag) = pattern.find(line) else {
        return false;
    };
    // The reference examines only the first occurrence on a trivia line. A
    // letter-adjacent first match also excludes later standalone occurrences.
    !line[..tag.start()]
        .chars()
        .next_back()
        .is_some_and(java_char_is_letter)
        && !line[tag.end()..]
            .chars()
            .next()
            .is_some_and(java_char_is_letter)
}

fn java_char_is_letter(character: char) -> bool {
    // The reference calls Character.isLetter(char), so a supplementary letter's
    // adjacent UTF-16 surrogate is not a letter. Digits and marks also pass.
    let mut encoded = [0; 4];
    character.len_utf16() == 1
        && (LETTER.is_match(character.encode_utf8(&mut encoded))
            // The pinned regex table uses Unicode 16. These eight additional
            // BMP letters make it equal to the reference JVM's Unicode 17
            // Character.isLetter(char) over all 65,536 UTF-16 code units.
            || matches!(character, '\u{088f}' | '\u{0c5c}' | '\u{0cdc}' | '\u{a7ce}' | '\u{a7cf}' | '\u{a7d2}' | '\u{a7d4}' | '\u{a7f1}'))
}

fn whole_line_ranges(source: &str) -> Vec<Range> {
    let bytes = source.as_bytes();
    let mut spans = Vec::new();
    let (mut start, mut offset) = (0, 0);
    while offset < bytes.len() {
        if matches!(bytes[offset], b'\r' | b'\n') {
            spans.push((start, offset));
            if bytes[offset] == b'\r' && bytes.get(offset + 1) == Some(&b'\n') {
                offset += 1;
            }
            start = offset + 1;
        }
        offset += 1;
    }
    spans.push((start, source.len()));
    spans
        .into_iter()
        .enumerate()
        .map(|(index, (start, end))| {
            let line = u32_saturating(index).saturating_add(1);
            Range {
                start: Pos { line, column: 0 },
                end: Pos {
                    line,
                    column: u32_saturating(source[start..end].chars().count()),
                },
            }
        })
        .collect()
}
