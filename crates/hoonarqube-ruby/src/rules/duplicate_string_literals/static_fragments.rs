//! Static parts of a regex or command literal. The syntax tree marks
//! interpolation and individual escapes; raw source supplies original spans.

use crate::support::SourceMap;
use hoonarqube_ir::Range;
use tree_sitter::Node;

use super::decode_escape;

pub(super) fn collect(
    node: Node<'_>,
    source: &str,
    map: &SourceMap,
    emit: &mut impl FnMut(String, Range),
) {
    let mut cursor = node.walk();
    let mut children = node.children(&mut cursor);
    let Some(opener) = children.next() else {
        return;
    };
    let delimiter = source[opener.byte_range()].chars().next_back();
    let shell = node.kind() == "subshell";
    let mut fragment = Fragment {
        start: opener.end_byte(),
        ..Default::default()
    };
    for child in children {
        let text = &source[child.byte_range()];
        match child.kind() {
            "string_content" => fragment.content(text, child.start_byte(), map, emit),
            "escape_sequence" => match text {
                "\\\n" => {}
                "\\\r" if source[child.end_byte()..].starts_with('\n') => fragment.skip_lf = true,
                _ if shell => decode_escape(text, &mut fragment.value),
                _ => fragment.value.push_str(regex_escape(text, delimiter)),
            },
            _ => {
                // Interpolation and the closing delimiter end the current fragment.
                fragment.finish(child.start_byte(), map, emit);
                fragment.start = child.end_byte();
            }
        }
    }
}

#[derive(Default)]
struct Fragment {
    start: usize,
    value: String,
    skip_lf: bool,
}

impl Fragment {
    fn content(
        &mut self,
        mut text: &str,
        mut offset: usize,
        map: &SourceMap,
        emit: &mut impl FnMut(String, Range),
    ) {
        // The grammar marks a backslash + CR as an escape and puts the LF
        // of that CRLF continuation in the following string_content node.
        if std::mem::take(&mut self.skip_lf)
            && let Some(rest) = text.strip_prefix('\n')
        {
            offset += 1;
            text = rest;
        }
        for line in text.split_inclusive('\n') {
            offset += line.len();
            if let Some(body) = line.strip_suffix('\n') {
                self.value.push_str(body.strip_suffix('\r').unwrap_or(body));
                self.value.push('\n');
                self.finish(offset, map, emit);
                self.start = offset;
            } else {
                self.value.push_str(line);
            }
        }
    }

    fn finish(&mut self, end: usize, map: &SourceMap, emit: &mut impl FnMut(String, Range)) {
        if !self.value.is_empty() {
            emit(std::mem::take(&mut self.value), map.range(self.start, end));
        }
    }
}

/// A backslash quoting a plain delimiter disappears. Regexp metacharacters
/// keep their escapes in the pattern even when serving as the delimiter.
fn regex_escape(text: &str, delimiter: Option<char>) -> &str {
    let escaped = &text[1..];
    if let Some(d) = delimiter
        && escaped.starts_with(d)
        && escaped.len() == d.len_utf8()
        && !".^$|?*+()[]{}\\".contains(d)
    {
        escaped
    } else {
        text
    }
}
