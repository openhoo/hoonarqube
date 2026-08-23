use crate::engine::rx::RxClass;
use crate::engine::rx::RxClassItem;
use crate::engine::rx::concise_class_message;
use crate::support::CLASS_METACHARACTERS;
use crate::support::is_grapheme_codepoint;
use crate::support::is_regional_indicator;
use ruff_text_size::TextRange;

pub(crate) fn check_rx_class(class: &RxClass, push: &mut dyn FnMut(&str, &str, TextRange)) {
    // python:S6397 — single-character class.
    if !class.negated
        && class.items.len() == 1
        && let RxClassItem::Char(ch) = class.items[0]
        && !CLASS_METACHARACTERS.contains(&ch)
    {
        push(
            "python:S6397",
            "Remove this single-character class and write the character directly.",
            class.span,
        );
    }
    // python:S6353 — classes with concise shorthand equivalents.
    if let Some(message) = concise_class_message(class) {
        push("python:S6353", message, class.span);
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
                    push(
                        "python:S5869",
                        "Remove this duplicate character or overlapping range.",
                        class.span,
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
                        "Remove this duplicate character or overlapping range.",
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
