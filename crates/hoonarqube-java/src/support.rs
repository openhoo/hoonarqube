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
        let mut line_starts = vec![0];
        for (offset, byte) in source.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(offset + 1);
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
        let line_index = self
            .line_starts
            .partition_point(|&start| start <= offset)
            .saturating_sub(1);
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
        let byte = bytes[i];
        if byte.is_ascii_whitespace() {
            pending_space = true;
            i += 1;
            continue;
        }
        if byte == b'/' && bytes.get(i + 1) == Some(&b'/') {
            pending_space = true;
            i += 2;
            while i < bytes.len() && bytes[i] != b'\n' {
                i += 1;
            }
            continue;
        }
        if byte == b'/' && bytes.get(i + 1) == Some(&b'*') {
            pending_space = true;
            i += 2;
            while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                i += 1;
            }
            i = (i + 2).min(bytes.len());
            continue;
        }
        let Some(ch) = source[i..].chars().next() else {
            break;
        };
        let literal = ch == '"' || ch == '\'';
        if pending_space
            && !output.is_empty()
            && previous
                .is_some_and(|value| value.is_ascii_alphanumeric() || value == '_' || value == '$')
            && (ch.is_ascii_alphanumeric() || ch == '_' || ch == '$')
        {
            output.push(' ');
        }
        pending_space = false;
        output.push(ch);
        previous = Some(ch);
        i += ch.len_utf8();
        if literal {
            let quote = ch;
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
            previous = Some(quote);
        }
    }
    output
}

pub(crate) fn file_metrics(root: Node<'_>, source: &str) -> FileMetrics {
    let lines = if source.is_empty() {
        0
    } else {
        u32_saturating(source.lines().count())
    };
    let mut code = BTreeSet::new();
    let mut comments = BTreeSet::new();
    walk_all(root, &mut |node| {
        let is_comment = matches!(node.kind(), "line_comment" | "block_comment" | "comment");
        if is_comment {
            for row in node.start_position().row..=node.end_position().row {
                comments.insert(row);
            }
        } else if node.child_count() == 0 && !node.is_error() && !node.is_missing() {
            for row in node.start_position().row..=node.end_position().row {
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
}
