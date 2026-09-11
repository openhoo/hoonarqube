//! Syntax-tree, coordinate, and source-metric helpers for Java.

use std::collections::BTreeSet;

use hoonarqube_ir::{FileMetrics, Pos, Range, u32_saturating};
use tree_sitter::Node;

/// Iterative pre-order traversal. The cursor preserves source order and does
/// not recurse on attacker-controlled nesting depth.
pub(crate) fn walk_all<'tree>(root: Node<'tree>, visit: &mut impl FnMut(Node<'tree>)) {
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

pub(crate) fn collect_kinds<'tree>(root: Node<'tree>, kinds: &[&str]) -> Vec<Node<'tree>> {
    let mut nodes = Vec::new();
    walk_all(root, &mut |node| {
        if kinds.contains(&node.kind()) {
            nodes.push(node);
        }
    });
    nodes
}

pub(crate) fn node_text<'source>(node: Node<'_>, source: &'source str) -> &'source str {
    node.utf8_text(source.as_bytes()).unwrap_or("")
}

/// Java has no alternate identifier spelling, but trimming is useful when a
/// caller supplies a token copied from a qualified name.
pub(crate) fn canonical_identifier(text: &str) -> &str {
    text.trim().trim_start_matches('@')
}

pub(crate) fn simple_name(text: &str) -> &str {
    let text = text.trim();
    let text = text
        .split('<')
        .next()
        .unwrap_or(text)
        .trim_end_matches("[]");
    canonical_identifier(text.rsplit('.').next().unwrap_or(text))
}

/// Exact source byte to document-position index. Lines are one-based and
/// columns are zero-based Unicode-scalar columns, matching `hoonarqube-ir`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LineIndex {
    line_starts: Vec<usize>,
    source_len: usize,
}

impl LineIndex {
    #[must_use]
    pub fn new(source: &str) -> Self {
        let bytes = source.as_bytes();
        let mut line_starts = vec![0];
        let mut offset = 0;
        while offset < bytes.len() {
            let separator_width = match bytes[offset] {
                b'\r' => Some(if bytes.get(offset + 1) == Some(&b'\n') {
                    2
                } else {
                    1
                }),
                b'\n' => Some(1),
                _ => None,
            };
            if let Some(width) = separator_width {
                offset += width;
                line_starts.push(offset);
            } else {
                offset += 1;
            }
        }
        Self {
            line_starts,
            source_len: source.len(),
        }
    }

    #[must_use]
    pub fn position(&self, source: &str, byte_offset: usize) -> Pos {
        let mut offset = byte_offset.min(self.source_len).min(source.len());
        while offset > 0 && !source.is_char_boundary(offset) {
            offset -= 1;
        }
        let line_index = self.line_index(offset);
        let line_start = self.line_starts[line_index];
        let column = source
            .get(line_start..offset)
            .map_or(offset.saturating_sub(line_start), |text| {
                text.strip_suffix('\r').unwrap_or(text).chars().count()
            });
        Pos {
            line: u32_saturating(line_index).saturating_add(1),
            column: u32_saturating(column),
        }
    }

    #[must_use]
    pub fn range(&self, source: &str, start: usize, end: usize) -> Range {
        let start = start.min(self.source_len);
        let end = end.min(self.source_len).max(start);
        Range {
            start: self.position(source, start),
            end: self.position(source, end),
        }
    }

    fn line_index(&self, byte_offset: usize) -> usize {
        self.line_starts
            .partition_point(|&start| start <= byte_offset.min(self.source_len))
            .saturating_sub(1)
    }

    fn line_span(&self, start: usize, end: usize) -> std::ops::RangeInclusive<usize> {
        let start = start.min(self.source_len);
        let end = end.min(self.source_len).max(start);
        let start_line = self.line_index(start);
        if end <= start {
            return start_line..=start_line;
        }
        start_line..=self.line_index(end.saturating_sub(1)).max(start_line)
    }

    fn line_count(&self) -> usize {
        if self.source_len == 0 {
            return 0;
        }
        self.line_starts.len().saturating_sub(usize::from(
            self.line_starts.last() == Some(&self.source_len),
        ))
    }
}

pub(crate) fn file_metrics(root: Node<'_>, source: &str) -> FileMetrics {
    let index = LineIndex::new(source);
    let lines = u32_saturating(index.line_count());
    let mut code = BTreeSet::new();
    let mut comments = BTreeSet::new();
    walk_all(root, &mut |node| {
        let is_comment = matches!(node.kind(), "line_comment" | "block_comment" | "comment");
        if is_comment {
            for row in index.line_span(node.start_byte(), node.end_byte()) {
                comments.insert(row);
            }
        } else if node.child_count() == 0 && !node.is_error() && !node.is_missing() {
            for row in index.line_span(node.start_byte(), node.end_byte()) {
                code.insert(row);
            }
        }
    });
    FileMetrics {
        lines,
        code_lines: u32_saturating(code.len()),
        comment_lines: u32_saturating(comments.difference(&code).count()),
    }
}

pub(crate) fn range_of(node: Node<'_>, source: &str, index: &LineIndex) -> Range {
    index.range(source, node.start_byte(), node.end_byte())
}

/// Removes comments and insignificant whitespace while retaining token
/// boundaries and literal contents. It is a stable identity for equivalent
/// expression spellings, not a Java parser or type normalizer.
#[cfg(test)]
pub(crate) fn canonical_expression(source: &str) -> String {
    let bytes = source.as_bytes();
    let mut output = String::with_capacity(source.len());
    let mut i = 0;
    let mut pending_space = false;
    let mut previous: Option<char> = None;
    while i < bytes.len() {
        if let Some(next) = skip_ignored(bytes, i, &mut pending_space) {
            i = next;
            continue;
        }
        let Some(ch) = source[i..].chars().next() else {
            break;
        };
        if needs_token_separator(pending_space, &output, previous, ch) {
            output.push(' ');
        }
        pending_space = false;
        output.push(ch);
        previous = Some(ch);
        i += ch.len_utf8();
        if ch == '"' || ch == '\'' {
            i = append_literal_tail(source, bytes, i, ch, &mut output);
            previous = Some(ch);
        }
    }
    output
}

#[cfg(test)]
fn skip_ignored(bytes: &[u8], i: usize, pending_space: &mut bool) -> Option<usize> {
    if bytes[i].is_ascii_whitespace() {
        *pending_space = true;
        return Some(i + 1);
    }
    if starts_with_pair(bytes, i, b'/', b'/') {
        *pending_space = true;
        let mut next = i + 2;
        while next < bytes.len() && bytes[next] != b'\n' {
            next += 1;
        }
        return Some(next);
    }
    if starts_with_pair(bytes, i, b'/', b'*') {
        *pending_space = true;
        let mut next = i + 2;
        while next + 1 < bytes.len() && !(bytes[next] == b'*' && bytes[next + 1] == b'/') {
            next += 1;
        }
        return Some((next + 2).min(bytes.len()));
    }
    None
}

#[cfg(test)]
fn starts_with_pair(bytes: &[u8], i: usize, first: u8, second: u8) -> bool {
    bytes.get(i) == Some(&first) && bytes.get(i + 1) == Some(&second)
}

#[cfg(test)]
fn needs_token_separator(
    pending_space: bool,
    output: &str,
    previous: Option<char>,
    current: char,
) -> bool {
    pending_space
        && !output.is_empty()
        && previous
            .is_some_and(|value| value.is_ascii_alphanumeric() || value == '_' || value == '$')
        && (current.is_ascii_alphanumeric() || current == '_' || current == '$')
}

#[cfg(test)]
fn append_literal_tail(
    source: &str,
    bytes: &[u8],
    mut i: usize,
    quote: char,
    output: &mut String,
) -> usize {
    while i < bytes.len() {
        let Some(next) = source[i..].chars().next() else {
            break;
        };
        output.push(next);
        i += next.len_utf8();
        if next == '\\' {
            if let Some(escaped) = source[i..].chars().next() {
                output.push(escaped);
                i += escaped.len_utf8();
            }
        } else if next == quote {
            break;
        }
    }
    i
}

#[cfg(test)]
mod tests {
    use super::{LineIndex, canonical_expression, file_metrics};
    use tree_sitter::Parser;

    #[test]
    fn byte_offsets_map_unicode_columns_and_crlf() {
        let source = "é = 1\r\n第二 = 2";
        let index = LineIndex::new(source);
        assert_eq!(index.position(source, 2).line, 1);
        assert_eq!(index.position(source, 2).column, 1);
        let cr = source.find('\r').unwrap();
        let lf = source.find('\n').unwrap();
        assert_eq!(index.position(source, cr).column, 5);
        assert_eq!(index.position(source, lf).column, 5);
        assert_eq!(index.range(source, 0, lf).end.column, 5);
        let second = source.find('第').unwrap();
        assert_eq!(index.position(source, second).line, 2);
        assert_eq!(index.position(source, second).column, 0);
    }

    #[test]
    fn bare_cr_line_index_maps_five_lines() {
        let source = "one\rtwo\rthree\rfour\rfive";
        let index = LineIndex::new(source);
        assert_eq!(index.line_starts, vec![0, 4, 8, 14, 19]);
        for (line, start) in [0, 4, 8, 14, 19].into_iter().enumerate() {
            let position = index.position(source, start);
            assert_eq!(
                position.line,
                u32::try_from(line).expect("line index fits in u32") + 1
            );
            assert_eq!(position.column, 0);
        }
        for (line, separator) in [3, 7, 13, 18].into_iter().enumerate() {
            let at_separator = index.position(source, separator);
            assert_eq!(
                at_separator.line,
                u32::try_from(line).expect("line index fits in u32") + 1
            );
            assert_eq!(at_separator.column, [3, 3, 5, 4][line]);
            let after_separator = index.position(source, separator + 1);
            assert_eq!(
                after_separator.line,
                u32::try_from(line).expect("line index fits in u32") + 2
            );
            assert_eq!(after_separator.column, 0);
        }
        assert_eq!(index.line_count(), 5);
    }

    #[test]
    fn line_index_treats_lf_and_crlf_as_single_breaks() {
        let source = "a\r\nbb\nccc\r\nd";
        let index = LineIndex::new(source);
        assert_eq!(index.line_starts, vec![0, 3, 6, 11]);
        assert_eq!(index.line_count(), 4);
        assert_eq!(index.position(source, 1).line, 1);
        assert_eq!(index.position(source, 1).column, 1);
        assert_eq!(index.position(source, 2).line, 1);
        assert_eq!(index.position(source, 2).column, 1);
        assert_eq!(index.position(source, 3).line, 2);
        assert_eq!(index.position(source, 3).column, 0);
        assert_eq!(index.position(source, 5).line, 2);
        assert_eq!(index.position(source, 5).column, 2);
        assert_eq!(index.position(source, 6).line, 3);
        assert_eq!(index.position(source, 9).column, 3);
        assert_eq!(index.position(source, 10).column, 3);
        assert_eq!(index.position(source, 11).line, 4);
    }

    #[test]
    fn unicode_columns_count_scalars_not_utf8_bytes() {
        let source = "π🙂 = 1\r\n漢字 = 2";
        let index = LineIndex::new(source);
        let emoji = source.find('🙂').unwrap();
        assert_eq!(index.position(source, emoji).column, 1);
        let cr = source.find('\r').unwrap();
        let lf = source.find('\n').unwrap();
        assert_eq!(index.position(source, cr).column, 6);
        assert_eq!(index.position(source, lf).column, 6);
        let second = source.find('漢').unwrap();
        assert_eq!(index.position(source, second).line, 2);
        assert_eq!(index.position(source, second).column, 0);
        let second_character = source.find('字').unwrap();
        assert_eq!(index.position(source, second_character).column, 1);
    }

    #[test]
    fn expression_identity_ignores_layout_and_comments() {
        assert_eq!(canonical_expression("a + /* x */ b"), "a+b");
        assert_eq!(canonical_expression("a+b"), "a+b");
    }

    #[test]
    fn metrics_count_code_overlapping_comments() {
        let source = "// one\nclass A { /* two */ int x; }\n";
        let mut parser = Parser::new();
        parser
            .set_language(&tree_sitter_java::LANGUAGE.into())
            .unwrap();
        let tree = parser.parse(source, None).unwrap();
        let metrics = file_metrics(tree.root_node(), source);
        assert_eq!(metrics.lines, 2);
        assert_eq!(metrics.comment_lines, 1);
        assert_eq!(metrics.code_lines, 1);
    }

    #[test]
    fn metrics_use_java_physical_lines_for_all_terminators() {
        for separator in ["\n", "\r\n", "\r"] {
            let source = format!("// one{separator}class A {{ int x; }}{separator}");
            let tree = crate::context::parse(&source).expect("valid Java fixture");
            assert!(!tree.root_node().has_error(), "{separator:?}");
            let metrics = file_metrics(tree.root_node(), &source);
            assert_eq!(metrics.lines, 2, "{separator:?}");
            assert_eq!(metrics.comment_lines, 1, "{separator:?}");
            assert_eq!(metrics.code_lines, 1, "{separator:?}");
        }
    }
}
