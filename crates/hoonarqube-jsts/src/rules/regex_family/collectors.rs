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

pub(crate) fn flush_space_run(sink: &mut IssueSink, site: &RegexSite, run: Option<(usize, u32)>) {
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
