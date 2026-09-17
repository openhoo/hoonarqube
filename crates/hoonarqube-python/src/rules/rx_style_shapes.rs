use crate::AnalyzerOptions;
use crate::engine::rx::RxAtom;
use crate::engine::rx::RxParsed;
use crate::engine::rx::for_each_class;
use crate::engine::rx::for_each_rx_item;
use crate::engine::rx::for_each_rx_seq_deep;
use crate::engine::rx::rx_complexity;
use crate::rules::curly_quantifier::{check_curly_quantifier, check_redundant_repetition};
use crate::rules::rx_class::check_rx_class;
use ruff_text_size::{TextRange, TextSize};

pub(crate) fn check_rx_style_shapes(
    parsed: &RxParsed,
    source: &str,
    verbose: bool,
    options: &AnalyzerOptions,
    pattern_range: TextRange,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    let _ = verbose;
    // python:S5843 — overall complexity budget.
    let score = rx_complexity(&parsed.root, 1);
    if score > options.regex_maximum_complexity {
        push(
            "python:S5843",
            &format!(
                "Simplify this regular expression to reduce its complexity from {score} to the {} allowed.",
                options.regex_maximum_complexity
            ),
            TextRange::at(pattern_range.start(), TextSize::new(1)),
        );
    }
    // python:S5857 — a reluctant quantifier on `.` or an escaped class
    // immediately before a fixed continuation character can be rewritten as
    // a negated class. Mirrors Sonar's ReluctantQuantifierFinder: the
    // repetition must be the last-but-one sequence item (trailing empty
    // flag groups are skipped) and the final item must be a plain
    // character, escaped class, character class, or a non-capturing group
    // wrapping one of those.
    for_each_rx_seq_deep(&parsed.root, &mut |seq| {
        check_reluctant_quantifier(seq, source, push);
    });
    for_each_rx_item(&parsed.root, &mut |item| {
        // python:S6396 / python:S6353 — curly-quantifier conciseness.
        if let Some(quant) = &item.quant {
            check_curly_quantifier(quant, source, push);
        }
    });
    for_each_rx_seq_deep(&parsed.root, &mut |seq| {
        check_redundant_repetition(seq, source, push);
    });
    // Class-level checks.
    for_each_class(&parsed.root, &mut |class| {
        check_rx_class(class, source, push);
    });
}

/// python:S5857 — Sonar's `ReluctantQuantifierFinder` semantics.
fn check_reluctant_quantifier(
    seq: &crate::engine::rx::RxSeq,
    source: &str,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    let items = &seq.items;
    if items.len() < 2 {
        return;
    }
    // Skip trailing empty non-capturing groups (flag setters like `(?i)`).
    let mut index = items.len() - 2;
    while index > 0 && is_empty_flag_group(&items[index]) {
        index -= 1;
    }
    let item = &items[index];
    let Some(quant) = &item.quant else {
        return;
    };
    if !quant.lazy || quant.min == quant.max.unwrap_or(u32::MAX) {
        return;
    }
    let Some(element) = reluctant_element(&item.atom) else {
        return;
    };
    let last = &items[items.len() - 1];
    if last.quant.is_some() {
        return;
    }
    let Ok(base) = base_character(element) else {
        return;
    };
    let Some(replacement) = negated_class_for(last, base, source) else {
        return;
    };
    let suffix = greedy_suffix(quant, source);
    push(
        "python:S5857",
        &format!("Replace this use of a reluctant quantifier with \"{replacement}{suffix}\"."),
        item.span,
    );
}

/// `(?i)`-style empty non-capturing group (a flag setter).
fn is_empty_flag_group(item: &crate::engine::rx::RxItem) -> bool {
    matches!(item.atom, RxAtom::GlobalFlags)
}

/// The repeated element with nested non-capturing groups unwrapped; only
/// `.` and escaped character classes qualify.
fn reluctant_element(atom: &RxAtom) -> Option<&RxAtom> {
    let mut current = atom;
    loop {
        match current {
            RxAtom::Group(group)
                if matches!(group.kind, crate::engine::rx::RxGroupKind::NonCapture) =>
            {
                match &group.body {
                    crate::engine::rx::RxNode::Seq(seq) if seq.items.len() == 1 => {
                        current = &seq.items[0].atom;
                    }
                    _ => return None,
                }
            }
            RxAtom::Dot | RxAtom::EscClass(_) => return Some(current),
            _ => return None,
        }
    }
}

/// `getBaseCharacter`: `None` for `.` (represented as `Ok(None)`), the
/// escaped class itself otherwise. `Err` marks an unhandled element.
fn base_character(element: &RxAtom) -> Result<Option<crate::engine::rx::RxEscClass>, ()> {
    match element {
        RxAtom::Dot => Ok(None),
        RxAtom::EscClass(class) => Ok(Some(*class)),
        _ => Err(()),
    }
}

/// `findNegatedCharacterClassFor`: the negated-class replacement text for
/// the continuation `last`, or `None` when the continuation cannot be
/// expressed or already cannot intersect the repeated element.
fn negated_class_for(
    last: &crate::engine::rx::RxItem,
    base: Option<crate::engine::rx::RxEscClass>,
    source: &str,
) -> Option<String> {
    // A continuation that cannot intersect the repeated element needs no
    // rewrite (e.g. `\d*?x` where `x` is disjoint from `\d`).
    if let Some(base_class) = base
        && let (Some(last_set), Some(base_set)) = (
            crate::engine::rx::rx_atom_first_set(&last.atom),
            crate::engine::rx::rx_atom_first_set(&RxAtom::EscClass(base_class)),
        )
        && !crate::engine::rx::rx_sets_intersect(&last_set, &base_set)
    {
        return None;
    }
    let negated_base =
        base.and_then(|class| negate_esc_class(class).map(|letter| format!("\\{letter}")));
    match &last.atom {
        RxAtom::Literal(ch) => Some(format!(
            "[^{}{}]",
            escape_class_char(*ch),
            negated_base.as_deref().unwrap_or("")
        )),
        RxAtom::EscClass(class) => {
            let negated = format!("\\{}", negate_esc_class(*class)?);
            Some(match negated_base {
                None => negated,
                Some(extra) => format!("[{negated}{extra}]"),
            })
        }
        RxAtom::Class(class) => {
            let inner = class_inner_text(class, source);
            if class.negated {
                Some(format!(
                    "[{inner}{}]",
                    base.map(|b| format!("\\{}", esc_class_letter(b)))
                        .unwrap_or_default()
                ))
            } else {
                Some(format!("[^{inner}{}]", negated_base.unwrap_or_default()))
            }
        }
        RxAtom::Group(group)
            if matches!(group.kind, crate::engine::rx::RxGroupKind::NonCapture) =>
        {
            match &group.body {
                crate::engine::rx::RxNode::Seq(inner) if inner.items.len() == 1 => {
                    negated_class_for(&inner.items[0], base, source)
                }
                _ => None,
            }
        }
        _ => None,
    }
}

fn negate_esc_class(class: crate::engine::rx::RxEscClass) -> Option<String> {
    use crate::engine::rx::RxEscClass::{
        Digit, NotDigit, NotSpace, NotWord, Space, UnicodeOpaque, Word,
    };
    Some(
        match class {
            Digit => 'D',
            NotDigit => 'd',
            Word => 'W',
            NotWord => 'w',
            Space => 'S',
            NotSpace => 's',
            UnicodeOpaque => return None,
        }
        .to_string(),
    )
}

fn esc_class_letter(class: crate::engine::rx::RxEscClass) -> char {
    use crate::engine::rx::RxEscClass::{
        Digit, NotDigit, NotSpace, NotWord, Space, UnicodeOpaque, Word,
    };
    match class {
        Digit => 'd',
        NotDigit => 'D',
        Word => 'w',
        NotWord => 'W',
        Space => 's',
        NotSpace => 'S',
        UnicodeOpaque => 'p',
    }
}

/// Raw inner text of a character class (between the brackets, excluding
/// the leading `^` for negated classes).
fn class_inner_text(class: &crate::engine::rx::RxClass, source: &str) -> String {
    let text = &source[usize::from(class.span.start())..usize::from(class.span.end())];
    let inner = text
        .strip_prefix('[')
        .unwrap_or(text)
        .strip_suffix(']')
        .unwrap_or_else(|| text.strip_prefix('[').unwrap_or(text));
    inner.strip_prefix('^').unwrap_or(inner).to_string()
}

fn escape_class_char(ch: char) -> String {
    match ch {
        ']' | '\\' | '^' | '-' => format!("\\{ch}"),
        _ => ch.to_string(),
    }
}

/// The greedy suffix for the rewrite: the quantifier text minus its
/// trailing `?` (`*?` → `*`, `+?` → `+`, `{n,m}?` → `{n,m}`).
fn greedy_suffix(quant: &crate::engine::rx::RxQuant, source: &str) -> String {
    let text = &source[usize::from(quant.span.start())..usize::from(quant.span.end())];
    text.strip_suffix('?').unwrap_or(text).to_string()
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::test_support::regex_finds;

    use crate::{AnalyzerOptions, analyze};

    #[test]
    fn s5857_flags_reluctant_wildcard_quantifiers() {
        assert!(regex_finds(
            "import re\nre.compile(r'<.+?>')\n",
            "python:S5857"
        ));
        assert!(!regex_finds(
            "import re\nre.compile(r'<[^>]*>')\n",
            "python:S5857"
        ));
    }

    #[test]
    fn s6353_flags_verbose_class_and_equal_range_shapes() {
        assert!(regex_finds(
            "import re\nre.compile(r'[0-9]')\n",
            "python:S6353"
        ));
        assert!(regex_finds(
            "import re\nre.compile(r'[a-a]')\n",
            "python:S6353"
        ));
        assert!(regex_finds(
            "import re\nre.compile(r'[\\w\\W]')\n",
            "python:S6353"
        ));
    }

    #[test]
    fn s5843_enforces_the_complexity_budget() {
        let complex = "import re\nre.compile(r'(a|b|c|d|e|f|g|h|i|j)+(k|l|m|n|o|p|q|r|s|t)+(u|v|x|y|z|A|B|C|D|E)+')\n";
        assert!(regex_finds(complex, "python:S5843"));
        assert!(!regex_finds(
            "import re\nre.compile(r'\\d{4}-\\d{2}')\n",
            "python:S5843"
        ));
        // Raising the budget silences the finding.
        let options = AnalyzerOptions {
            regex_maximum_complexity: 500,
            ..AnalyzerOptions::default()
        };
        let report = analyze(PathBuf::from("t.py"), complex, &options);
        assert!(
            report
                .issues
                .iter()
                .all(|issue| issue.rule_key != "python:S5843")
        );
    }
}
