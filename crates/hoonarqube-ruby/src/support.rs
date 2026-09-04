//! Source-coordinate, syntax-tree, and lexical-metric helpers for Ruby.

use std::collections::{BTreeSet, VecDeque};
use std::str;

use hoonarqube_ir::{FileMetrics, Pos, Range, u32_saturating};
use tree_sitter::{Node, Point};

/// Maps parser byte offsets to the document coordinates used by the IR.
///
/// The map owns its UTF-8 source text and line-start metadata. Byte offsets
/// are clamped before conversion, and an offset in the middle of a UTF-8
/// scalar is treated as the end of the preceding valid prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceMap {
    source: String,
    line_starts: Vec<usize>,
}

impl Default for SourceMap {
    fn default() -> Self {
        Self::new("")
    }
}

impl SourceMap {
    /// Builds a source map from UTF-8 source text.
    #[must_use]
    pub fn new(source: &str) -> Self {
        let mut line_starts = vec![0];
        for (offset, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(offset + 1);
            }
        }
        Self {
            source: source.to_owned(),
            line_starts,
        }
    }

    /// Returns the owned source used by this map.
    #[must_use]
    pub fn source(&self) -> &str {
        &self.source
    }

    /// Returns the source length used to clamp byte offsets.
    #[must_use]
    pub fn source_len(&self) -> usize {
        self.source.len()
    }

    /// Converts a source byte offset to a one-based-line, zero-based-column
    /// position. CRLF terminators do not contribute to the column.
    #[must_use]
    pub fn position(&self, byte_offset: usize) -> Pos {
        let offset = byte_offset.min(self.source.len());
        let line_index = self
            .line_starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
        let line_start = self.line_starts.get(line_index).copied().unwrap_or(0);
        let next_line_start = self
            .line_starts
            .get(line_index + 1)
            .copied()
            .unwrap_or(self.source.len());

        // Keep LF and the CR in CRLF out of the character-column calculation.
        let mut content_end = next_line_start;
        if self.source.as_bytes().get(content_end.saturating_sub(1)) == Some(&b'\n') {
            content_end = content_end.saturating_sub(1);
            if self.source.as_bytes().get(content_end.saturating_sub(1)) == Some(&b'\r') {
                content_end = content_end.saturating_sub(1);
            }
        }
        let column_end = offset.min(content_end).max(line_start);
        let column = utf8_prefix_char_count(&self.source, line_start, column_end);
        Pos {
            line: u32_saturating(line_index).saturating_add(1),
            column: u32_saturating(column),
        }
    }

    /// Converts a tree-sitter point to an IR position. Tree-sitter columns are
    /// byte columns, so this delegates through safe byte-offset conversion.
    #[must_use]
    pub fn point_position(&self, point: Point) -> Pos {
        let row = point.row.min(self.line_starts.len().saturating_sub(1));
        let line_start = self
            .line_starts
            .get(row)
            .copied()
            .unwrap_or(self.source.len());
        let line_end = self.line_content_end(row);
        self.position(line_start.saturating_add(point.column).min(line_end))
    }

    /// Alias for [`SourceMap::point_position`].
    #[must_use]
    pub fn point(&self, point: Point) -> Pos {
        self.point_position(point)
    }

    fn line_content_end(&self, row: usize) -> usize {
        let line_start = self
            .line_starts
            .get(row)
            .copied()
            .unwrap_or(self.source.len());
        let next_line_start = self
            .line_starts
            .get(row + 1)
            .copied()
            .unwrap_or(self.source.len());
        let mut content_end = next_line_start;
        if self.source.as_bytes().get(content_end.saturating_sub(1)) == Some(&b'\n') {
            content_end = content_end.saturating_sub(1);
            if self.source.as_bytes().get(content_end.saturating_sub(1)) == Some(&b'\r') {
                content_end = content_end.saturating_sub(1);
            }
        }
        content_end.max(line_start)
    }

    /// Converts a half-open source-byte span to an IR range.
    #[must_use]
    pub fn range(&self, start: usize, end: usize) -> Range {
        let start = start.min(self.source.len());
        let end = end.min(self.source.len()).max(start);
        Range {
            start: self.position(start),
            end: self.position(end),
        }
    }

    /// Converts a tree-sitter node span to an IR range.
    #[must_use]
    pub fn node_range(&self, node: Node<'_>) -> Range {
        self.range(node.start_byte(), node.end_byte())
    }
}

fn utf8_prefix_char_count(source: &str, start: usize, end: usize) -> usize {
    let Some(bytes) = source.as_bytes().get(start..end) else {
        return 0;
    };
    match str::from_utf8(bytes) {
        Ok(text) => text.chars().count(),
        Err(error) => {
            str::from_utf8(&bytes[..error.valid_up_to()]).map_or(0, |text| text.chars().count())
        }
    }
}

/// Converts a tree-sitter node span to an IR range using a fresh source map.
/// Reuse [`SourceMap::node_range`] when converting many nodes from one file.
#[must_use]
pub fn node_range(node: Node<'_>, source: &str) -> Range {
    SourceMap::new(source).node_range(node)
}

/// Returns the exact UTF-8 text covered by a node, or an empty string when the
/// parser span cannot be represented as a valid source slice.
#[must_use]
pub fn node_text<'source>(node: Node<'_>, source: &'source str) -> &'source str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

/// Iterative pre-order traversal preserving tree-sitter source order.
///
/// A cursor is used instead of recursion so deeply nested or adversarial Ruby
/// input cannot exhaust the Rust call stack. Both a closure and `&mut` closure
/// can be passed as `visit` because `&mut F` implements `FnMut`.
pub fn walk<'tree>(root: Node<'tree>, mut visit: impl FnMut(Node<'tree>)) {
    let mut cursor = root.walk();
    loop {
        visit(cursor.node());
        if cursor.goto_first_child() {
            continue;
        }
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                return;
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HeredocIndentation {
    Exact,
    AllowIndentation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HeredocState {
    delimiter: String,
    indentation: HeredocIndentation,
}

#[derive(Default)]
struct LexicalState {
    quote: Option<u8>,
    escaped: bool,
    embedded_comment: bool,
    percent_literal: Option<(u8, u8, usize)>,
    percent_escaped: bool,
    heredocs: VecDeque<HeredocState>,
}

fn exact_marker(content: &str, marker: &str) -> bool {
    content == marker
        || content
            .strip_prefix(marker)
            .is_some_and(|rest| rest.chars().next().is_some_and(char::is_whitespace))
}

fn heredoc_terminator(content: &str, heredoc: &HeredocState) -> bool {
    let content = match heredoc.indentation {
        HeredocIndentation::Exact => content,
        HeredocIndentation::AllowIndentation => content.trim_start_matches([' ', '\t']),
    };
    content.trim_end_matches([' ', '\t']) == heredoc.delimiter
}

fn scan_lexical_line(line: &str, state: &mut LexicalState) -> (bool, bool) {
    let content = line
        .strip_suffix('\n')
        .unwrap_or(line)
        .strip_suffix('\r')
        .unwrap_or_else(|| line.strip_suffix('\n').unwrap_or(line));

    if let Some(heredoc) = state.heredocs.front() {
        if heredoc_terminator(content, heredoc) {
            state.heredocs.pop_front();
            return (true, false);
        }
        return (false, false);
    }

    let mut has_code = false;
    let has_comment;
    let end_marker = content.trim_start_matches([' ', '\t', '*']);
    let is_end = exact_marker(end_marker, "=end");
    let is_begin = exact_marker(content, "=begin");

    if state.embedded_comment {
        has_comment = true;
        if is_end {
            state.embedded_comment = false;
        }
    } else if state.quote.is_none() && state.percent_literal.is_none() && is_begin {
        has_comment = true;
        state.embedded_comment = true;
    } else {
        (has_code, has_comment) = scan_lexical_bytes(line, state);
    }
    (has_code, has_comment)
}

fn heredoc_opener(bytes: &[u8], index: usize) -> Option<(usize, HeredocState)> {
    if bytes.get(index) != Some(&b'<') || bytes.get(index + 1) != Some(&b'<') {
        return None;
    }
    let mut cursor = index + 2;
    let indentation = if matches!(bytes.get(cursor), Some(b'-' | b'~')) {
        cursor += 1;
        HeredocIndentation::AllowIndentation
    } else {
        HeredocIndentation::Exact
    };
    let (delimiter_start, delimiter_end) = match bytes.get(cursor) {
        Some(quote @ (b'\'' | b'"' | b'`')) => {
            cursor += 1;
            let start = cursor;
            while bytes.get(cursor).is_some_and(|byte| byte != quote) {
                cursor += 1;
            }
            if cursor == start || bytes.get(cursor) != Some(quote) {
                return None;
            }
            (start, cursor)
        }
        Some(byte) if byte.is_ascii_alphanumeric() || *byte == b'_' => {
            let start = cursor;
            cursor += 1;
            while bytes
                .get(cursor)
                .is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
            {
                cursor += 1;
            }
            (start, cursor)
        }
        _ => return None,
    };
    Some((
        if bytes
            .get(delimiter_end)
            .is_some_and(|byte| matches!(byte, b'\'' | b'"' | b'`'))
        {
            delimiter_end + 1
        } else {
            delimiter_end
        },
        HeredocState {
            delimiter: String::from_utf8_lossy(&bytes[delimiter_start..delimiter_end]).into_owned(),
            indentation,
        },
    ))
}

fn scan_lexical_bytes(line: &str, state: &mut LexicalState) -> (bool, bool) {
    let mut has_code = false;
    let mut has_comment = false;
    let bytes = line.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let byte = bytes[index];
        if let Some((opening, closing, mut depth)) = state.percent_literal {
            has_code = true;
            if state.percent_escaped {
                state.percent_escaped = false;
            } else if byte == b'\\' {
                state.percent_escaped = true;
            } else if opening != closing && byte == opening {
                depth = depth.saturating_add(1);
                state.percent_literal = Some((opening, closing, depth));
            } else if byte == closing {
                state.percent_literal = if opening != closing && depth > 1 {
                    Some((opening, closing, depth - 1))
                } else {
                    None
                };
            }
            index += 1;
            continue;
        }
        if state.escaped {
            state.escaped = false;
            has_code = true;
            index += 1;
            continue;
        }
        if let Some(delimiter) = state.quote {
            has_code = true;
            if byte == b'\\' {
                state.escaped = true;
            } else if byte == delimiter {
                state.quote = None;
            }
            index += 1;
            continue;
        }
        match byte {
            b'\'' | b'"' => {
                state.quote = Some(byte);
                has_code = true;
            }
            b'%' => {
                let percent_type = matches!(
                    bytes.get(index + 1),
                    Some(b'q' | b'Q' | b'w' | b'W' | b'i' | b'I' | b'x' | b'r' | b's')
                );
                let delimiter_index = index + if percent_type { 2 } else { 1 };
                let Some(&delimiter) = bytes.get(delimiter_index) else {
                    has_code = true;
                    index += 1;
                    continue;
                };
                let paired = matches!(delimiter, b'{' | b'[' | b'(' | b'<');
                let quoted = matches!(delimiter, b'\'' | b'"' | b'`');
                let punctuation = !delimiter.is_ascii_alphanumeric()
                    && !delimiter.is_ascii_whitespace()
                    && delimiter != b'_'
                    && delimiter != b'\\';
                if !(percent_type && punctuation || !percent_type && (paired || quoted)) {
                    has_code = true;
                    index += 1;
                    continue;
                }
                let closing = match delimiter {
                    b'{' => b'}',
                    b'[' => b']',
                    b'(' => b')',
                    b'<' => b'>',
                    _ => delimiter,
                };
                state.percent_literal = Some((delimiter, closing, usize::from(paired)));
                has_code = true;
                index = delimiter_index;
            }
            b'<' if state.quote.is_none() && state.percent_literal.is_none() => {
                if let Some((end, heredoc)) = heredoc_opener(bytes, index) {
                    state.heredocs.push_back(heredoc);
                    has_code = true;
                    index = end;
                    continue;
                }
                has_code = true;
            }
            b'#' => {
                has_comment = true;
                break;
            }
            b'\r' | b'\n' | b'\t' | b' ' => {}
            _ => has_code = true,
        }
        index += 1;
    }
    (has_code, has_comment)
}

/// Computes Sonar-style lexical line metrics.
///
/// A row containing both code and a comment is present in both metrics. The
/// scanner recognizes Ruby quoted and percent literals plus `=begin`/`=end`
/// embedded-document comments, so `#` inside a literal is not mistaken for a
/// comment; unterminated literals remain code safely.
#[must_use]
pub fn lexical_metrics(source: &str) -> FileMetrics {
    let lines = if source.is_empty() {
        0
    } else {
        source.lines().count()
    };
    let mut code_lines = BTreeSet::new();
    let mut comment_lines = BTreeSet::new();
    let mut state = LexicalState::default();

    for (row, line) in source.split_inclusive('\n').enumerate() {
        let (has_code, has_comment) = scan_lexical_line(line, &mut state);
        if has_code {
            code_lines.insert(row);
        }
        if has_comment {
            comment_lines.insert(row);
        }
    }

    FileMetrics {
        lines: u32_saturating(lines),
        code_lines: u32_saturating(code_lines.len()),
        comment_lines: u32_saturating(comment_lines.len()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paired_percent_literals_close_at_zero_depth() {
        let metrics = lexical_metrics("%q{outer {inner} } \n# comment\nvalue = 1\n");
        assert_eq!(metrics.comment_lines, 1);
        assert_eq!(metrics.code_lines, 2);
    }

    #[test]
    fn embedded_document_requires_an_exact_end_marker() {
        let metrics = lexical_metrics("=begin\n=endless\n=end\nvalue = 1\n");
        assert_eq!(metrics.comment_lines, 3);
        assert_eq!(metrics.code_lines, 1);
    }

    #[test]
    fn heredoc_payload_is_not_scanned_as_ruby_comments() {
        let metrics = lexical_metrics("sql = <<~SQL\n# payload\nSQL\nvalue = 1\n");
        assert_eq!(metrics.comment_lines, 0);
        assert_eq!(metrics.code_lines, 3);
    }
}
