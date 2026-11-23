//! `ruby:S1192` — string literals should not be duplicated.
//!
//! The rule groups static values within one file. Quoted strings contribute
//! a single value; regexes and shell commands expose static source fragments
//! separated by interpolation or an unescaped newline. Each occurrence after
//! the first is a separate supporting location in Community Build 26.9.

mod static_fragments;

use std::collections::HashMap;

use crate::AnalyzerOptions;
use crate::support::{SourceMap, walk};
use hoonarqube_ir::{FlowLocation, Issue, Range};
use tree_sitter::Node;

/// The reference never reports values shorter than six characters.
const MIN_DUPLICATED_LENGTH: usize = 6;

pub(crate) fn check(root: Node<'_>, source: &str, options: &AnalyzerOptions) -> Vec<Issue> {
    if root.has_error() {
        return Vec::new();
    }
    let threshold = options.duplicate_string_threshold.max(2);
    let map = SourceMap::new(source);
    let mut groups: HashMap<String, Vec<Range>> = HashMap::new();
    collect_occurrences(root, source, &map, &mut |value, range| {
        // Java measures the minimum in UTF-16 units and its default word
        // character class is ASCII, as the independent Unicode probes show.
        if value.encode_utf16().take(MIN_DUPLICATED_LENGTH).count() == MIN_DUPLICATED_LENGTH
            && !value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_')
        {
            groups.entry(value).or_default().push(range);
        }
    });

    let mut issues = Vec::new();
    for (value, mut ranges) in groups {
        let total = ranges.len();
        if total < threshold {
            continue;
        }
        // A literal inside interpolation can precede a later static fragment
        // in the enclosing literal, although we visit the enclosing node first.
        ranges.sort_by_key(|range| range.start);
        let mut ranges = ranges.into_iter();
        let Some(first) = ranges.next() else { continue };
        let mut issue = Issue::new(
            "ruby:S1192",
            format!(
                "Define a constant instead of duplicating this literal \"{value}\" {total} times."
            ),
            first,
        );
        for range in ranges {
            issue = issue.with_flow(vec![FlowLocation::in_primary_file("Duplication", range)]);
        }
        issues.push(issue);
    }
    issues.sort_by_key(|issue| issue.range.start);
    issues
}

/// Emits each eligible literal as `(decoded value, reported span)`. Reported spans mirror the reference: the full literal
/// (delimiters included) for quoted and percent-quoted strings and `%w`
/// words, the content between the delimiters for regex and command
/// substitution.
fn collect_occurrences(
    root: Node<'_>,
    source: &str,
    map: &SourceMap,
    emit: &mut impl FnMut(String, Range),
) {
    walk(root, &mut |node: Node<'_>| {
        match node.kind() {
            // Adjacent-string concatenation is dynamic on the reference and
            // contributes neither its parts nor the joined value.
            "string"
                if node
                    .parent()
                    .is_none_or(|parent| parent.kind() != "chained_string") =>
            {
                if has_child_of_kind(node, "interpolation") {
                    return;
                }
                let closer = closer_character(node, source);
                if let Some(value) = decoded_string_value(node, source, closer) {
                    emit(value, map.node_range(node));
                }
            }
            "bare_string" => {
                // `%w` words follow single-quote rules with whitespace as
                // the only meaningful extra escape.
                let value = decode_single_family(&source[node.byte_range()], None);
                emit(value, map.node_range(node));
            }
            "regex" | "subshell" => {
                static_fragments::collect(node, source, map, emit);
            }
            _ => {}
        }
    });
}

/// Builds a literal value from its tree-sitter children.
///
/// Double-quoted families (`"..."`, `%Q{...}`) mark every active escape as
/// an `escape_sequence` child, so decoding walks those nodes. Single-quote
/// families (`'...'`, `%q{...}`) surface raw content only and decode here
/// with Ruby's quote-literal rules.
fn decoded_string_value(node: Node<'_>, source: &str, closer: Option<char>) -> Option<String> {
    let mut marked = false;
    let mut value = String::new();
    let mut skip_lf = false;
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        let text = &source[child.byte_range()];
        match child.kind() {
            "string_content" => {
                let text = if skip_lf {
                    text.strip_prefix('\n').unwrap_or(text)
                } else {
                    text
                };
                skip_lf = false;
                if text.contains('\n') {
                    // Multiple physical content lines do not form a single
                    // static string node on the reference.
                    return None;
                }
                value.push_str(text);
            }
            "escape_sequence" => {
                marked = true;
                match text {
                    "\\\n" => {}
                    "\\\r" if source[child.end_byte()..].starts_with('\n') => skip_lf = true,
                    _ => decode_escape(text, &mut value),
                }
            }
            _ => {}
        }
    }
    Some(if marked {
        value
    } else {
        decode_single_family(&value, closer)
    })
}

/// Decodes single-quote-family escapes: only `\`, the quote character, and
/// the closing delimiter (when known) lose their backslash; every other
/// backslash sequence stays literal.
fn decode_single_family(content: &str, closer: Option<char>) -> String {
    let mut value = String::with_capacity(content.len());
    let mut characters = content.chars();
    while let Some(character) = characters.next() {
        if character != '\\' {
            value.push(character);
            continue;
        }
        match characters.next() {
            Some(next) if Some(next) == closer || next == '\\' || next == '\'' => {
                value.push(next);
            }
            Some(next) => {
                value.push('\\');
                value.push(next);
            }
            None => value.push('\\'),
        }
    }
    value
}

/// The literal's closing delimiter character, when its opener is one of the
/// single-quote families (`'` or `%q`); double-quoted families need no
/// secondary decoding because the grammar marks their escapes.
fn closer_character(node: Node<'_>, source: &str) -> Option<char> {
    let mut cursor = node.walk();
    let first = node.children(&mut cursor).next()?;
    let opener = &source[first.byte_range()];
    if !(opener.starts_with('\'') || opener.starts_with("%q")) {
        return None;
    }
    let mut cursor = node.walk();
    let last = node.children(&mut cursor).last()?;
    source[last.byte_range()].chars().next_back()
}

/// Decodes one Ruby escape sequence. Unknown escapes drop the backslash,
/// matching Ruby's double-quoted behavior; single-quoted literals only ever
/// mark `\\` and `\'`, which decode identically.
fn decode_escape(escape: &str, out: &mut String) {
    let mut characters = escape[1..].chars();
    let Some(first) = characters.next() else {
        return;
    };
    if let Some(simple) = simple_escape(first) {
        out.push(simple);
        return;
    }
    match first {
        '0'..='7' => push_codepoint(out, take_digits(&mut characters, first.to_digit(8), 8, 2)),
        'x' => push_codepoint(out, take_digits(&mut characters, None, 16, 2)),
        'u' => push_unicode_escape(out, &mut characters),
        // Unknown escapes drop the backslash.
        _ => out.push(first),
    }
}

/// Single-character escapes and the characters that quote themselves.
fn simple_escape(first: char) -> Option<char> {
    match first {
        'a' => Some('\u{7}'),
        'b' => Some('\u{8}'),
        'e' => Some('\u{1b}'),
        'f' => Some('\u{c}'),
        'n' => Some('\n'),
        'r' => Some('\r'),
        's' => Some(' '),
        't' => Some('\t'),
        'v' => Some('\u{b}'),
        '\\' | '\'' | '"' | '#' => Some(first),
        _ => None,
    }
}

/// Consumes up to `limit` radix-`radix` digits, starting from an optional
/// already-consumed first digit.
fn take_digits(
    characters: &mut std::str::Chars<'_>,
    first: Option<u32>,
    radix: u32,
    limit: usize,
) -> u32 {
    let mut value = first.unwrap_or(0);
    for _ in 0..limit {
        let Some(digit) = characters
            .next()
            .and_then(|character| character.to_digit(radix))
        else {
            break;
        };
        value = value * radix + digit;
    }
    value
}

fn push_codepoint(out: &mut String, value: u32) {
    if let Some(character) = char::from_u32(value) {
        out.push(character);
    }
}

/// Decodes `\uHHHH` and `\u{H+ ...}` forms. Each braced space-separated
/// group contributes one character.
fn push_unicode_escape(out: &mut String, characters: &mut std::str::Chars<'_>) {
    if !characters.as_str().starts_with('{') {
        push_codepoint(out, take_digits(characters, None, 16, 4));
        return;
    }
    characters.next();
    let mut value: u32 = 0;
    let mut digits = 0;
    for next in characters.by_ref() {
        if next == '}' {
            break;
        }
        if next == ' ' || next == '\t' {
            flush_unicode_group(out, &mut value, &mut digits);
            continue;
        }
        if let Some(digit) = next.to_digit(16) {
            value = value * 16 + digit;
            digits += 1;
        }
    }
    flush_unicode_group(out, &mut value, &mut digits);
}

fn flush_unicode_group(out: &mut String, value: &mut u32, digits: &mut u32) {
    if *digits > 0
        && let Some(character) = char::from_u32(*value)
    {
        out.push(character);
    }
    *value = 0;
    *digits = 0;
}

fn has_child_of_kind(node: Node<'_>, kind: &str) -> bool {
    child_of_kind(node, kind).is_some()
}

fn child_of_kind<'tree>(node: Node<'tree>, kind: &str) -> Option<Node<'tree>> {
    let mut cursor = node.walk();
    node.children(&mut cursor)
        .find(|child| child.kind() == kind)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn findings(source: &str) -> Vec<String> {
        parse_and_check(source)
            .into_iter()
            .map(|issue| issue.message)
            .collect()
    }

    fn parse_and_check(source: &str) -> Vec<Issue> {
        let mut parser = tree_sitter::Parser::new();
        parser
            .set_language(&tree_sitter_ruby::LANGUAGE.into())
            .unwrap();
        let Some(tree) = parser.parse(source, None) else {
            return Vec::new();
        };
        check(tree.root_node(), source, &crate::AnalyzerOptions::default())
    }

    #[test]
    fn escape_decoding_decides_grouping() {
        // Decoded values differ (`\n` newline vs literal backslash-n), so the
        // reference never groups these into one finding.
        let source = "def probe\n  [\"esc-one\\n\", \"esc-one\\n\", 'esc-one\\n']\nend\n";
        assert_eq!(findings(source), Vec::<String>::new());
    }

    #[test]
    fn percent_q_decodes_doubled_backslash_in_message() {
        let source = "def probe\n  [%q{bs-one-\\\\n}, %q{bs-one-\\\\n}, %q{bs-one-\\\\n}]\nend\n";
        let messages = findings(source);
        assert_eq!(messages.len(), 1);
        assert_eq!(
            messages[0],
            "Define a constant instead of duplicating this literal \"bs-one-\\n\" 3 times."
        );
    }

    #[test]
    fn interpolated_percent_q_and_heredocs_stay_silent() {
        let source = "\
def probe(value)
  [%Q{interp-one #{value}}, %Q{interp-one #{value}}, %Q{interp-one #{value}}]
end
H1 = <<~A
  alpha-one-x
  alpha-one-x
  alpha-one-x
A
";
        assert_eq!(findings(source), Vec::<String>::new());
    }

    #[test]
    fn interpolated_regex_groups_only_static_fragments() {
        let source = concat!(
            "def probe(x, y)\n",
            "  a = \"prefix-value \"\n",
            "  b = /prefix-value #{x}/\n",
            "  c = /prefix-value #{y}/\n",
            "end\n",
        );
        assert_eq!(
            findings(source),
            [r#"Define a constant instead of duplicating this literal "prefix-value " 3 times."#]
        );

        let plain_regex_still_counts = concat!(
            "def probe\n",
            "  a = \"prefix-value \"\n",
            "  b = /prefix-value /\n",
            "  c = %x{prefix-value }\n",
            "end\n",
        );
        let messages = findings(plain_regex_still_counts);
        assert_eq!(messages.len(), 1);
        assert!(messages[0].contains("prefix-value"));
    }

    #[test]
    fn multiline_regex_groups_source_lines_across_interpolation() {
        let source =
            "re = %r[\r\néá-😀-example\r\n#{value}\r\néá-😀-example\r\néá-😀-example\r\n]x\r\n";
        let issues = parse_and_check(source);
        assert_eq!(issues.len(), 1);
        let issue = &issues[0];
        assert_eq!(
            issue.message,
            "Define a constant instead of duplicating this literal \"éá-😀-example\n\" 3 times."
        );
        assert_eq!(
            (
                issue.range.start.line,
                issue.range.end.line,
                issue.range.end.column
            ),
            (2, 3, 0)
        );
        let lines: Vec<_> = issue
            .flows
            .iter()
            .map(|flow| {
                let [loc] = flow.locations.as_slice() else {
                    panic!("one flow per occurrence")
                };
                (loc.range.start.line, loc.range.end.line)
            })
            .collect();
        assert_eq!(lines, [(4, 5), (5, 6)]);
    }

    #[test]
    fn adjacent_strings_and_symbols_never_count() {
        let source = "\
def probe
  x = \"cc\" \"-one-x\"
  y = \"cc\" \"-one-x\"
  z = \"cc\" \"-one-x\"
  %i[sym-one-x sym-one-x sym-one-x]
  [:other-sym, :other-sym, :other-sym]
end
";
        assert_eq!(findings(source), Vec::<String>::new());
    }
}
