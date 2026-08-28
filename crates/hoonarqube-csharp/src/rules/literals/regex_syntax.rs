use super::support::argument_expression;
use super::support::argument_nodes;
use super::support::is_regex_creation;
use super::support::is_string_literal;
use super::support::literal_inner_text;
use super::support::regex_static_pattern;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5856 — regular expressions must be syntactically valid.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    regex_pattern_arguments(root, source)
        .into_iter()
        .filter(|(_, pattern)| {
            is_string_literal(*pattern) && !is_valid_regex(literal_inner_text(*pattern, source))
        })
        .map(|(_, pattern)| {
            let value = literal_inner_text(pattern, source);
            issue(
                language,
                "S5856",
                regex_error_message(value),
                range_of(pattern, source),
            )
        })
        .collect()
}

fn regex_error_message(pattern: &str) -> String {
    if pattern.contains('[') && !pattern.contains(']') {
        return format!(
            "Fix the syntax error inside this regex: Invalid pattern '{pattern}' at offset {}. Unterminated [] set.",
            pattern.chars().count()
        );
    }
    let chars: Vec<char> = pattern.chars().collect();
    for index in 1..chars.len().saturating_sub(1) {
        if chars[index] == '-'
            && chars[index - 1].is_ascii_alphanumeric()
            && chars[index + 1].is_ascii_alphanumeric()
            && chars[index - 1] > chars[index + 1]
        {
            return format!(
                "Fix the syntax error inside this regex: Invalid pattern '{pattern}' at offset {}. [x-y] range in reverse order.",
                index + 2
            );
        }
    }
    format!("Fix the syntax error inside this regex: Invalid pattern '{pattern}'.")
}

/// Hand-rolled syntactic validation of regular-expression patterns:
/// balanced groups and classes, well-placed quantifiers, valid escapes, and
/// sane character-class ranges — no regex engine required.
fn is_valid_regex(pattern: &str) -> bool {
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    let mut depth: usize = 0;
    let mut atom = false;
    while i < chars.len() {
        match chars[i] {
            '\\' => {
                if i + 1 >= chars.len() {
                    return false;
                }
                i += 2;
                atom = true;
            }
            '[' => {
                if !scan_regex_class(&chars, i, &mut i) {
                    return false;
                }
                atom = true;
            }
            '(' => {
                depth += 1;
                if chars.get(i + 1) == Some(&'?') {
                    let Some(end) = group_header_end(&chars, i) else {
                        return false;
                    };
                    if chars[end] == ')' {
                        // A header ending on `)` (such as `(?)`) closed its group.
                        depth -= 1;
                    }
                    i = end + 1;
                } else {
                    i += 1;
                }
                atom = false;
            }
            ')' => {
                if depth == 0 {
                    return false;
                }
                depth -= 1;
                i += 1;
                atom = true;
            }
            '|' => {
                i += 1;
                atom = false;
            }
            '*' | '+' | '?' => {
                if !atom {
                    return false;
                }
                while i < chars.len() && matches!(chars[i], '*' | '+' | '?') {
                    i += 1;
                }
            }
            '{' => {
                if let Some(end) = bounded_repeat_end(&chars, i).filter(|_| atom) {
                    i = end + 1;
                } else {
                    i += 1;
                }
                atom = true;
            }
            _ => {
                i += 1;
                atom = true;
            }
        }
    }
    depth == 0
}

/// End index of the terminator of a `(?` group header such as `(?:`,
/// `(?=`, `(?<=`, or `(?<name>`; `None` when the pattern ends first.
fn group_header_end(chars: &[char], open: usize) -> Option<usize> {
    let mut j = open + 2;
    while j < chars.len() && !matches!(chars[j], ':' | '=' | '!' | '>' | ')') {
        j += 1;
    }
    chars.get(j).map(|_| j)
}

/// End index of a bounded quantifier `{2}`, `{2,}`, or `{2,4}` whose
/// `{` sits at `start`; `None` when the braces do not close into one.
fn bounded_repeat_end(chars: &[char], start: usize) -> Option<usize> {
    let mut j = start + 1;
    while j < chars.len() && chars[j].is_ascii_digit() {
        j += 1;
    }
    if j < chars.len() && chars[j] == ',' {
        j += 1;
        while j < chars.len() && chars[j].is_ascii_digit() {
            j += 1;
        }
    }
    (j < chars.len() && chars[j] == '}' && j > start + 1).then_some(j)
}

/// Scans one `[...]` character class starting at `start`, advancing `i`
/// past it. Rejects unterminated classes and reversed ranges (`[z-a]`);
/// false means the pattern is invalid.
fn scan_regex_class(chars: &[char], start: usize, i: &mut usize) -> bool {
    let mut j = start + 1;
    if chars.get(j) == Some(&'^') {
        j += 1;
    }
    if chars.get(j) == Some(&']') {
        j += 1;
    }
    let mut prev: Option<char> = None;
    while j < chars.len() {
        match chars[j] {
            ']' => {
                *i = j + 1;
                return true;
            }
            '\\' => {
                if j + 1 >= chars.len() {
                    *i = chars.len();
                    return false;
                }
                j += 2;
                prev = None;
            }
            '-' if prev.is_some() && chars.get(j + 1).is_some_and(|hi| *hi != ']') => {
                let hi = chars[j + 1];
                if hi != '\\' && prev.is_some_and(|lo| lo > hi) {
                    *i = chars.len();
                    return false;
                }
                prev = None;
                j += 1;
            }
            _ => {
                prev = Some(chars[j]);
                j += 1;
            }
        }
    }
    *i = chars.len();
    false
}

/// Pattern arguments worth validating: first argument of a `new Regex(...)`
/// creation and second argument of a static `Regex.Method(...)` call.
fn regex_pattern_arguments<'t>(root: Node<'t>, source: &str) -> Vec<(Node<'t>, Node<'t>)> {
    let mut out = Vec::new();
    for creation in collect_kinds(root, &["object_creation_expression"]) {
        if !is_regex_creation(creation, source) {
            continue;
        }
        let Some(arguments) = creation.child_by_field_name("arguments") else {
            continue;
        };
        if let Some(pattern) = argument_nodes(arguments).first() {
            out.push((creation, argument_expression(*pattern)));
        }
    }
    for invocation in collect_kinds(root, &["invocation_expression"]) {
        if let Some(pattern) = regex_static_pattern(invocation, source) {
            out.push((invocation, pattern));
        }
    }
    out
}
