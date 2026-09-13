// Residual rule machinery for 'regex_family' (extracted from lib.rs).
use crate::engine::pattern_parser::{ClassItem, PatternNode, RegexSite};
use crate::support::{IssueSink, RuleScope};
use oxc_span::Span;

/// `S5843`: patterns scoring above this complexity budget are flagged
/// (subset approximation of the frozen catalog `threshold=20`).
pub(crate) const REGEX_COMPLEXITY_THRESHOLD: u32 = 20;

/// Concise-form rewrite for classes made solely of duplicated single chars
/// (`[aa]` → `[a]`), following the upstream message shape.
pub(crate) fn emit_concise_class_rewrite(
    sink: &mut IssueSink,
    site: &RegexSite,
    items: &[ClassItem],
    start: usize,
    end: usize,
) {
    let mut unique: Vec<char> = Vec::new();
    for item in items {
        let ClassItem::Char { ch, .. } = item else {
            return; // mixed shapes have no single concise form in subset scope
        };
        if !unique.contains(ch) {
            unique.push(*ch);
        }
    }
    if unique.len() == items.len() {
        return; // no duplicates, nothing to rewrite
    }
    let expected: String = unique.iter().collect();
    let actual = &site.pattern[start..end];
    sink.emit_span(
        RuleScope::Both,
        "S6353",
        &format!("Use concise character class syntax '[{expected}]' instead of '{actual}'."),
        site.sub_span(start, end),
    );
}

/// Concise `\d` rewrite for a class made solely of the `0-9` range: in
/// JavaScript both match exactly the ten ASCII digits. Negated classes and
/// any wider member set keep their class form.
pub(crate) fn emit_digit_range_rewrite(
    sink: &mut IssueSink,
    site: &RegexSite,
    negated: bool,
    items: &[ClassItem],
    start: usize,
    end: usize,
) {
    if negated {
        return;
    }
    if !matches!(
        items,
        [ClassItem::Range {
            low: '0',
            high: '9',
            ..
        }]
    ) {
        return;
    }
    let actual = &site.pattern[start..end];
    sink.emit_span(
        RuleScope::Both,
        "S6353",
        &format!("Use concise character class syntax '\\d' instead of '{actual}'."),
        site.sub_span(start, end),
    );
}

/// `S6535` over regex patterns: reports escape sequences whose unescaped
/// spelling parses to the same pattern. Runs on the raw pattern text after
/// the mini parser accepted the pattern, so class boundaries and escape
/// pairs are well-formed.
///
/// Inside a class, regex metacharacters are literal, so their escapes are
/// unnecessary — except `\-` at the first or last item position and `^` as
/// the first item, where unescaping would form a range or negate the
/// class. Outside a class only `\-` is a needless identity escape; the
/// remaining punctuation is significant there and shorthand/controlled
/// escapes (`\d`, `\n`, `\]`, `\\`, …) are never touched.
pub(crate) fn check_unnecessary_pattern_escapes(sink: &mut IssueSink, site: &RegexSite) {
    let chars: Vec<(usize, char)> = site.pattern.char_indices().collect();
    let mut index = 0usize;
    let mut in_class = false;
    let mut first_item_offset = 0usize;
    while index < chars.len() {
        let (offset, ch) = chars[index];
        match ch {
            '\\' => {
                let Some(&(escaped_offset, escaped)) = chars.get(index + 1) else {
                    return; // trailing backslash: unreachable after a successful parse
                };
                // Flagged escapes are one ASCII char after the backslash.
                if escaped_offset == offset + 1 && escaped.is_ascii() {
                    let last_item =
                        chars.get(index + 2).is_some_and(|&(_, next)| next == ']') && in_class;
                    let unnecessary = if in_class {
                        class_escape_is_unnecessary(escaped, offset, first_item_offset, last_item)
                    } else {
                        escaped == '-'
                    };
                    if unnecessary {
                        sink.emit_span(
                            RuleScope::Both,
                            "S6535",
                            "Remove the unnecessary escape sequence from this regular expression.",
                            site.sub_span(offset, offset + 2),
                        );
                    }
                }
                index += 2;
            }
            '[' if !in_class => {
                in_class = true;
                let negated = chars.get(index + 1).is_some_and(|&(_, next)| next == '^');
                first_item_offset = offset + 1 + usize::from(negated);
                index += 1;
            }
            ']' if in_class => {
                in_class = false;
                index += 1;
            }
            _ => index += 1,
        }
    }
}

/// Whether unescaping `escaped` inside a class keeps the class semantics.
fn class_escape_is_unnecessary(
    escaped: char,
    offset: usize,
    first_item: usize,
    last_item: bool,
) -> bool {
    match escaped {
        // Unescaping a boundary `\-` (first item, or the item right before
        // the class close) keeps it a literal dash; elsewhere it would form
        // a range.
        '-' => offset == first_item || last_item,
        // A leading `^` would negate the class when unescaped.
        '^' => offset != first_item,
        '.' | '[' | '(' | ')' | '{' | '}' | '|' | '?' | '*' | '+' | '$' => true,
        _ => false,
    }
}

pub(crate) fn emit_space_runs_in_sequence(
    sink: &mut IssueSink,
    site: &RegexSite,
    sequence: &[PatternNode],
) {
    let mut run: Option<(usize, u32)> = None; // (start offset, length)
    for node in sequence {
        match node {
            PatternNode::Literal { ch: ' ', pos } => {
                run = Some(match run {
                    Some((start, len)) => (start, len + 1),
                    None => (*pos, 1),
                });
            }
            _ => flush_space_run(sink, site, run.take()),
        }
    }
    flush_space_run(sink, site, run.take());
}

fn flush_space_run(sink: &mut IssueSink, site: &RegexSite, run: Option<(usize, u32)>) {
    let Some((start, len)) = run.filter(|&(_, length)| length >= 2) else {
        return;
    };
    let end = start + usize::try_from(len).unwrap_or(usize::MAX);
    sink.emit_span(
        RuleScope::Both,
        "S6326",
        &format!("If multiple spaces are required here, use number quantifier ({{{len}}})."),
        site.sub_span(start, end),
    );
}

pub(crate) fn flag_single_char_alternation(
    sink: &mut IssueSink,
    alternatives: &[Vec<PatternNode>],
    span: Span,
) {
    let all_single_char = alternatives.len() > 1
        && alternatives
            .iter()
            .all(|branch| matches!(branch.as_slice(), [PatternNode::Literal { .. }]));
    if all_single_char {
        sink.emit_span(
            RuleScope::Both,
            "S6035",
            "Replace this alternation with a character class.",
            span,
        );
    }
}

pub(crate) fn is_bare_control_character(ch: char) -> bool {
    matches!(
        ch,
        '\0'..='\u{0008}' | '\u{000B}' | '\u{000C}' | '\u{000E}'..='\u{001F}'
    )
}

/// Calls `f` for every sequence in the tree — groups' alternatives and
/// quantified targets included; class internals excluded.
pub(crate) fn for_every_sequence(sequence: &[PatternNode], f: &mut dyn FnMut(&[PatternNode])) {
    f(sequence);
    for node in sequence {
        match node {
            PatternNode::Group { alternatives, .. } => {
                for alternative in alternatives {
                    for_every_sequence(alternative, f);
                }
            }
            PatternNode::Quantified { node: inner, .. } => {
                for_every_sequence(std::slice::from_ref(inner.as_ref()), f);
            }
            _ => {}
        }
    }
}
