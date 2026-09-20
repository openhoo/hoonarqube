//! `ruby:S1192` — string literals should not be duplicated.
//!
//! Contract pinned against the live `SonarQube` 26.8 Community reference
//! (probe-verified on 2026-09-15, oracle: the pinned `rake` scan with 41
//! findings): literals group per file by their *decoded* value across all
//! plain literal forms — quoted strings (single, double, `%q`, `%Q`),
//! `%w[...]` words, regex content, and command substitution content. A value
//! reported at least `threshold` times (catalog default 3) is flagged once at
//! its first occurrence; every later occurrence becomes a `Duplication`
//! secondary location. Silent controls: values shorter than six characters,
//! word-character-only values (letters, digits, underscore), any literal with
//! interpolation, heredoc bodies, adjacent (`chained`) string parts, and
//! symbol/char literals.

use std::collections::HashMap;
use std::collections::HashSet;

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
    let mut occurrences: Vec<(String, Range)> = Vec::new();
    collect_occurrences(root, source, &map, &mut occurrences);
    if occurrences.len() < threshold {
        return Vec::new();
    }

    let mut totals: HashMap<&str, usize> = HashMap::new();
    for (value, _) in &occurrences {
        *totals.entry(value).or_insert(0) += 1;
    }
    let mut emitted: HashSet<&str> = HashSet::new();
    let mut issues = Vec::new();
    for (index, (value, range)) in occurrences.iter().enumerate() {
        if !emitted.insert(value) {
            continue;
        }
        let total = totals[value.as_str()];
        if total < threshold
            || value.chars().count() < MIN_DUPLICATED_LENGTH
            || value
                .chars()
                .all(|character| character.is_alphanumeric() || character == '_')
        {
            continue;
        }
        let flows: Vec<FlowLocation> = occurrences[index + 1..]
            .iter()
            .filter(|(candidate, _)| candidate == value)
            .map(|(_, flow_range)| FlowLocation::in_primary_file("Duplication", flow_range.clone()))
            .collect();
        let mut issue = Issue::new(
            "ruby:S1192",
            format!(
                "Define a constant instead of duplicating this literal \"{value}\" {total} times."
            ),
            range.clone(),
        );
        if !flows.is_empty() {
            issue = issue.with_flow(flows);
        }
        issues.push(issue);
    }
    issues
}

/// Collects every eligible literal as `(decoded value, reported span)` in
/// source order. Reported spans mirror the reference: the full literal
/// (delimiters included) for quoted and percent-quoted strings and `%w`
/// words, the content between the delimiters for regex and command
/// substitution.
fn collect_occurrences(
    root: Node<'_>,
    source: &str,
    map: &SourceMap,
    out: &mut Vec<(String, Range)>,
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
                let value = decoded_string_value(node, source, closer);
                out.push((value, node_range(map, node)));
            }
            "bare_string" => {
                // `%w` words follow single-quote rules with whitespace as
                // the only meaningful extra escape.
                let value = decode_single_family(&source[node.byte_range()], None);
                out.push((value, node_range(map, node)));
            }
            "regex" | "subshell" => {
                // Interpolation makes the value dynamic; like the string
                // branch, interpolated regex/subshell content never counts.
                if has_child_of_kind(node, "interpolation") {
                    return;
                }
                if let Some(content) = child_of_kind(node, "string_content") {
                    out.push((
                        source[content.byte_range()].to_string(),
                        node_range(map, content),
                    ));
                }
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
fn decoded_string_value(node: Node<'_>, source: &str, closer: Option<char>) -> String {
    let mut marked = false;
    let mut raw = String::new();
    let mut cursor = node.walk();
    for child in node.children(&mut cursor) {
        match child.kind() {
            "string_content" => raw.push_str(&source[child.byte_range()]),
            "escape_sequence" => {
                marked = true;
                decode_escape(&source[child.byte_range()], &mut raw);
            }
            _ => {}
        }
    }
    if marked {
        raw
    } else {
        decode_single_family(&raw, closer)
    }
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

fn node_range(map: &SourceMap, node: Node<'_>) -> Range {
    Range {
        start: map.position(node.start_byte()),
        end: map.position(node.end_byte()),
    }
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
    fn interpolated_regex_and_subshell_never_count() {
        let source = concat!(
            "def probe(x, y)\n",
            "  a = \"prefix-value \"\n",
            "  b = /prefix-value #{x}/\n",
            "  c = /prefix-value #{y}/\n",
            "end\n",
        );
        assert!(findings(source).is_empty());

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
