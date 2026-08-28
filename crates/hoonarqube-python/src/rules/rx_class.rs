use crate::engine::rx::RxClass;
use crate::engine::rx::RxClassItem;
use crate::engine::rx::concise_class_replacement;
use crate::support::CLASS_METACHARACTERS;
use crate::support::is_grapheme_codepoint;
use crate::support::is_regional_indicator;
use crate::support::to_u32;
use ruff_text_size::{TextRange, TextSize};

pub(crate) fn check_rx_class(
    class: &RxClass,
    source: &str,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    // python:S6397 — single-character class.
    if !class.negated
        && class.items.len() == 1
        && let RxClassItem::Char(ch) = class.items[0]
        && !CLASS_METACHARACTERS.contains(&ch)
    {
        push(
            "python:S6397",
            "Replace this character class by the character itself.",
            TextRange::at(
                class.span.start() + TextSize::new(1),
                TextSize::from(to_u32(ch.len_utf8())),
            ),
        );
    }
    // python:S6353 — classes with concise shorthand equivalents.
    if let Some(replacement) = concise_class_replacement(class) {
        let class_text = &source[class.span];
        let message = format!(
            "Use concise character class syntax '{replacement}' instead of '{class_text}'."
        );
        push("python:S6353", &message, class.span);
    }
    // python:S5869 — duplicated characters and overlapping ranges.
    let mut seen_chars: Vec<char> = Vec::new();
    let mut seen_ranges: Vec<(char, char)> = Vec::new();
    for item in &class.items {
        match item {
            RxClassItem::Char(ch) => {
                if seen_chars.contains(ch)
                    || seen_ranges
                        .iter()
                        .any(|(low, high)| low <= ch && ch <= high)
                {
                    let class_text = &source[class.span];
                    let relative = class_text.find(*ch).unwrap_or(0);
                    let first = class.span.start() + TextSize::from(to_u32(relative));
                    push(
                        "python:S5869",
                        "Remove duplicates in this character class.",
                        TextRange::at(first, TextSize::from(to_u32(ch.len_utf8()))),
                    );
                    return;
                }
                seen_chars.push(*ch);
            }
            RxClassItem::Range(low, high) => {
                if seen_ranges.iter().any(|(l2, h2)| l2 <= high && low <= h2)
                    || seen_chars.iter().any(|seen| low <= seen && seen <= high)
                {
                    push(
                        "python:S5869",
                        "Remove duplicates in this character class.",
                        class.span,
                    );
                    return;
                }
                seen_ranges.push((*low, *high));
            }
            RxClassItem::Esc(_) => {}
        }
    }
    // python:S5868 — grapheme clusters inside classes.
    if class
        .items
        .iter()
        .any(|item| matches!(item, RxClassItem::Char(ch) if is_grapheme_codepoint(*ch)))
        || class.items.windows(2).any(|pair| {
            pair.iter()
                .all(|item| matches!(item, RxClassItem::Char(ch) if is_regional_indicator(*ch)))
        })
    {
        push(
            "python:S5868",
            "Avoid Unicode grapheme clusters inside this character class.",
            class.span,
        );
    }
}
