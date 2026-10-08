use crate::engine::rx::RxClass;
use crate::engine::rx::concise_class_replacement;
use crate::engine::rx::{RxClassItem, RxEscClass};
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
        && let Some(span) = single_character_class_interior(class, source)
    {
        push(
            "python:S6397",
            "Replace this character class by the character itself.",
            span,
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
    for (range, lower, raw) in redundant_character_ranges(class, source) {
        push(
            "python:S6353",
            &format!("Use simple character '{lower}' instead of '{raw}'."),
            range,
        );
    }
    check_duplicates_in_class(class, source, push);
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
fn check_duplicates_in_class(
    class: &RxClass,
    source: &str,
    push: &mut dyn FnMut(&str, &str, TextRange),
) {
    // python:S5869 — duplicated characters and overlapping ranges.
    let mut seen_chars: Vec<char> = Vec::new();
    let mut seen_ranges: Vec<(char, char)> = Vec::new();
    let mut seen_esc = Vec::new();
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
            RxClassItem::Esc(escape) => {
                if seen_esc.contains(escape) || digit_is_covered(*escape, &seen_esc) {
                    let Some(range) = duplicate_escape_range(*escape, &seen_esc, class, source)
                    else {
                        return;
                    };
                    push(
                        "python:S5869",
                        "Remove duplicates in this character class.",
                        range,
                    );
                    return;
                }
                seen_esc.push(*escape);
            }
        }
    }
}

fn digit_is_covered(escape: RxEscClass, seen: &[RxEscClass]) -> bool {
    escape == RxEscClass::Digit && seen.contains(&RxEscClass::Word)
}

fn duplicate_escape_range(
    escape: RxEscClass,
    seen: &[RxEscClass],
    class: &RxClass,
    source: &str,
) -> Option<TextRange> {
    let highlighted = if digit_is_covered(escape, seen) {
        RxEscClass::Word
    } else {
        escape
    };
    let symbol = match highlighted {
        RxEscClass::Digit => "\\d",
        RxEscClass::Word => "\\w",
        RxEscClass::Space => "\\s",
        _ => return None,
    };
    let relative = source[class.span].find(symbol).unwrap_or(0);
    Some(TextRange::at(
        class.span.start() + TextSize::from(to_u32(relative)),
        TextSize::new(2),
    ))
}

fn single_character_class_interior(class: &RxClass, source: &str) -> Option<TextRange> {
    let start = class.span.start();
    let end = class.span.end();
    let interior_start = start.checked_add(TextSize::new(1))?;
    let interior_end = end.checked_sub(TextSize::new(1))?;
    if interior_start >= interior_end {
        return None;
    }

    let class_text = source.get(start.to_usize()..end.to_usize())?;
    if !class_text.starts_with('[') || !class_text.ends_with(']') {
        return None;
    }
    source.get(interior_start.to_usize()..interior_end.to_usize())?;
    Some(TextRange::new(interior_start, interior_end))
}

pub(crate) fn redundant_character_ranges(
    class: &RxClass,
    source: &str,
) -> Vec<(TextRange, String, String)> {
    let mut cursor = class.span.start().to_usize().saturating_add(1);
    let end = class.span.end().to_usize();
    if cursor < end && source[cursor..end].starts_with('^') {
        cursor += 1;
    }
    let mut ranges = Vec::new();
    for item in &class.items {
        if let RxClassItem::Range(low, high) = item {
            let Some((actual_low, low_end)) = class_token(source, cursor, end) else {
                break;
            };
            let Some(dash_end) = source
                .get(low_end..end)
                .and_then(|rest| rest.strip_prefix('-'))
                .map(|_| low_end + 1)
            else {
                break;
            };
            let Some((actual_high, high_end)) = class_token(source, dash_end, end) else {
                break;
            };
            if actual_low == *low && actual_high == *high && low == high {
                let span = TextRange::new(
                    TextSize::from(to_u32(cursor)),
                    TextSize::from(to_u32(high_end)),
                );
                ranges.push((
                    span,
                    source[cursor..low_end].to_string(),
                    source[cursor..high_end].to_string(),
                ));
            }
            cursor = high_end;
        } else {
            let Some((_, next)) = class_token(source, cursor, end) else {
                break;
            };
            cursor = next;
        }
    }
    ranges
}

fn class_token(source: &str, start: usize, end: usize) -> Option<(char, usize)> {
    if start >= end {
        return None;
    }
    let first = source[start..end].chars().next()?;
    let first_len = first.len_utf8();
    if first != '\\' {
        return Some((first, start + first_len));
    }
    let escaped_start = start + first_len;
    let escaped = source[escaped_start..end].chars().next()?;
    let escaped_len = escaped.len_utf8();
    let token_end = escaped_start + escaped_len;
    let decoded = match escaped {
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'b' => '\u{08}',
        'f' => '\u{0C}',
        'v' => '\u{0B}',
        'a' => '\u{07}',
        'x' => {
            let digits = source.get(token_end..token_end + 2)?;
            char::from_u32(u32::from_str_radix(digits, 16).ok()?)?
        }
        'u' => {
            let digits = source.get(token_end..token_end + 4)?;
            char::from_u32(u32::from_str_radix(digits, 16).ok()?)?
        }
        'U' => {
            let digits = source.get(token_end..token_end + 8)?;
            char::from_u32(u32::from_str_radix(digits, 16).ok()?)?
        }
        '0'..='7' => {
            let mut finish = token_end;
            while finish < end
                && finish.saturating_sub(token_end) < 2
                && source[finish..end]
                    .chars()
                    .next()
                    .is_some_and(|ch| ('0'..='7').contains(&ch))
            {
                finish += source[finish..end]
                    .chars()
                    .next()
                    .expect("checked")
                    .len_utf8();
            }
            let digits = source.get(escaped_start..finish)?;
            char::from_u32(u32::from_str_radix(digits, 8).ok()?)?
        }
        _ => escaped,
    };
    let end = match escaped {
        'x' => token_end + 2,
        'u' => token_end + 4,
        'U' => token_end + 8,
        '0'..='7' => {
            let mut finish = token_end;
            while finish < end
                && finish.saturating_sub(token_end) < 2
                && source[finish..end]
                    .chars()
                    .next()
                    .is_some_and(|ch| ('0'..='7').contains(&ch))
            {
                finish += source[finish..end]
                    .chars()
                    .next()
                    .expect("checked")
                    .len_utf8();
            }
            finish
        }
        _ => token_end,
    };
    Some((decoded, end))
}

#[cfg(test)]
mod tests {
    use super::{RxClass, RxClassItem, check_rx_class};
    use crate::support::to_u32;
    use ruff_text_size::{TextRange, TextSize};

    fn s6397_range(source: &str, items: Vec<RxClassItem>) -> Option<TextRange> {
        let class = RxClass {
            negated: false,
            items,
            member_spans: Vec::new(),
            span: TextRange::new(TextSize::new(0), TextSize::from(to_u32(source.len()))),
        };
        let mut found = None;
        check_rx_class(&class, source, &mut |key, _, range| {
            if key == "python:S6397" {
                found = Some(range);
            }
        });
        found
    }

    #[test]
    fn s6397_spans_the_complete_source_encoded_class_interior() {
        for (source, character) in [
            ("[b]", 'b'),
            ("[é]", 'é'),
            (r"[\t]", '\t'),
            (r"[\u0061]", 'a'),
            (r"[\x61]", 'a'),
            (r"[\N{LATIN SMALL LETTER A}]", 'a'),
            (r"[\101]", 'A'),
        ] {
            let range = s6397_range(source, vec![RxClassItem::Char(character)])
                .expect("single-character class should be reported");
            assert_eq!(
                range,
                TextRange::new(TextSize::new(1), TextSize::from(to_u32(source.len() - 1)))
            );
            assert_eq!(&source[range], &source[1..source.len() - 1]);
        }
    }

    #[test]
    fn s6397_keeps_multi_character_and_metacharacter_classes_clean() {
        assert!(
            s6397_range("[ab]", vec![RxClassItem::Char('a'), RxClassItem::Char('b')]).is_none()
        );
        assert!(s6397_range("[.]", vec![RxClassItem::Char('.')]).is_none());
        assert!(s6397_range("[]", vec![RxClassItem::Char('a')]).is_none());
    }
}

pub(crate) fn duplicate_class_locations(
    node: &crate::engine::rx::RxNode,
    primary: TextRange,
) -> Vec<TextRange> {
    use crate::engine::rx::{RxAtom, for_each_rx_item};
    let mut locations = Vec::new();
    for_each_rx_item(node, &mut |item| {
        if let RxAtom::Class(class) = &item.atom
            && class.span.contains_range(primary)
        {
            locations.extend(class_duplicate_locations(class, primary));
        }
    });
    locations
}

fn class_duplicate_locations(class: &RxClass, primary: TextRange) -> Vec<TextRange> {
    let Some(seed) = class
        .member_spans
        .iter()
        .position(|range| *range == primary)
    else {
        return Vec::new();
    };
    let Some(first) = class.items.get(seed).and_then(class_member_set) else {
        return Vec::new();
    };
    class
        .items
        .iter()
        .zip(&class.member_spans)
        .enumerate()
        .filter_map(|(position, (item, span))| {
            (position != seed
                && class_member_set(item)
                    .is_some_and(|set| crate::engine::rx::rx_sets_intersect(&first, &set)))
            .then_some(*span)
        })
        .collect()
}

fn class_member_set(item: &RxClassItem) -> Option<crate::engine::rx::RxSet> {
    use crate::engine::rx::{RxAtom, RxSet, rx_atom_first_set};
    match item {
        RxClassItem::Char(ch) => rx_atom_first_set(&RxAtom::Literal(*ch)),
        RxClassItem::Esc(escape) => rx_atom_first_set(&RxAtom::EscClass(*escape)),
        RxClassItem::Range(low, high) => Some(RxSet::Members {
            exact: std::collections::BTreeSet::new(),
            ranges: vec![(*low, *high)],
        }),
    }
}
