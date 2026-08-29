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
    /// Opening parenthesis made redundant by this immediately nested pair.
    redundant_open: Option<usize>,
}

pub(crate) fn check_redundant_parentheses(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let segments = unmasked_segments(parsed, source);
    let mut scanner = ParenScanner::default();

    for &(base, text) in &segments {
        for (relative, character) in text.char_indices() {
            scanner.consume(base + relative, character, &segments, index, source);
        }
    }
    scanner.issues
}

#[derive(Default)]
struct ParenScanner {
    issues: Vec<Issue>,
    stack: Vec<ParenFrame>,
    last_significant: Option<char>,
}

impl ParenScanner {
    fn consume(
        &mut self,
        position: usize,
        character: char,
        segments: &[(usize, &str)],
        index: &LineIndex,
        source: &str,
    ) {
        match character {
            '(' => self.open(position),
            ')' => self.close(position, segments, index, source),
            ',' => {
                if let Some(innermost) = self.stack.last_mut() {
                    innermost.commas += 1;
                }
                self.last_significant = Some(',');
            }
            whitespace if whitespace.is_whitespace() => {}
            other => {
                if let Some(innermost) = self.stack.last_mut() {
                    innermost.content = true;
                }
                self.last_significant = Some(other);
            }
        }
    }

    fn open(&mut self, position: usize) {
        let redundant_open = (self.last_significant == Some('('))
            .then(|| self.stack.last().map(|frame| frame.open))
            .flatten();
        self.stack.push(ParenFrame {
            open: position,
            commas: 0,
            content: false,
            redundant_open,
        });
        self.last_significant = Some('(');
    }

    fn close(
        &mut self,
        position: usize,
        segments: &[(usize, &str)],
        index: &LineIndex,
        source: &str,
    ) {
        if let Some(frame) = self.stack.pop()
            && let Some(redundant_open) = frame.redundant_open
            && frame.commas == 0
            && frame.content
            && next_significant_closes(segments, position + 1)
        {
            let start = TextSize::from(to_u32(redundant_open));
            self.issues.push(issue_at(
                "python:S1110",
                "Remove those useless parentheses.",
                TextRange::at(start, TextSize::new(1)),
                index,
                source,
            ));
        }
        self.last_significant = Some(')');
    }
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
