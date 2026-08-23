use crate::support::issue_at;
use crate::support::to_u32;
use crate::support::unmasked_segments;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;

// --- python:S1110 — redundant pairs of parentheses -----------------------------
//
// Token-level scan over the unmasked segments: an opening parenthesis that
// directly follows another opening parenthesis (whitespace apart) and closes
// directly before its partner's closing parenthesis wraps exactly one
// expression and can be removed. Pairs carrying top-level commas (tuples,
// unpacking targets, argument lists) or no content at all (`()`, string-only
// interiors are masked) change meaning or shape and stay exempt.

struct ParenFrame {
    open: usize,
    /// Commas seen while this frame was the innermost open pair.
    commas: usize,
    /// Any significant non-whitespace content besides the commas themselves.
    content: bool,
    /// Whether the previous significant token was another `(`.
    follows_open: bool,
}

pub(crate) fn check_redundant_parentheses(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let segments = unmasked_segments(parsed, source);
    let mut issues = Vec::new();
    let mut stack: Vec<ParenFrame> = Vec::new();
    let mut last_significant: Option<char> = None;

    for &(base, text) in &segments {
        for (relative, character) in text.char_indices() {
            let position = base + relative;
            match character {
                '(' => {
                    let follows_open = last_significant == Some('(');
                    stack.push(ParenFrame {
                        open: position,
                        commas: 0,
                        content: false,
                        follows_open,
                    });
                    last_significant = Some('(');
                }
                ')' => {
                    if let Some(frame) = stack.pop()
                        && frame.follows_open
                        && frame.commas == 0
                        && frame.content
                        && next_significant_closes(&segments, position + 1)
                    {
                        let start = TextSize::from(to_u32(frame.open));
                        let end = TextSize::from(to_u32(position + character.len_utf8()));
                        issues.push(issue_at(
                            "python:S1110",
                            "Remove these useless parentheses.",
                            TextRange::new(start, end),
                            index,
                            source,
                        ));
                    }
                    last_significant = Some(')');
                }
                ',' => {
                    if let Some(innermost) = stack.last_mut() {
                        innermost.commas += 1;
                    }
                    last_significant = Some(',');
                }
                whitespace if whitespace.is_whitespace() => {}
                other => {
                    if let Some(innermost) = stack.last_mut() {
                        innermost.content = true;
                    }
                    last_significant = Some(other);
                }
            }
        }
    }
    issues
}

/// Whether the first significant character at or after `from` is `)`.
fn next_significant_closes(segments: &[(usize, &str)], from: usize) -> bool {
    for &(base, text) in segments {
        let end = base + text.len();
        if end <= from {
            continue;
        }
        let local_start = from.saturating_sub(base).min(text.len());
        for character in text[local_start..].chars() {
            if !character.is_whitespace() {
                return character == ')';
            }
        }
    }
    false
}
