// Rule module s6328_replacement_groups (generated).
use crate::engine::pattern_parser::{GroupReference, ParsedRegex};
use crate::support::{IssueSink, RuleScope};
use oxc_span::Span;

/// `S6328`: replacement strings referencing groups the paired regex never
/// captures.
pub(crate) fn check_replacement_groups(
    sink: &mut IssueSink,
    replacement_span: Span,
    text: &str,
    parsed: &ParsedRegex,
) {
    let invalid: Vec<String> = replacement_group_references(text, parsed)
        .into_iter()
        .filter(|reference| !reference_exists(reference, parsed))
        .map(|reference| match reference {
            GroupReference::Index(index) => format!("${index}"),
            GroupReference::Name(name) => format!("$<{name}>"),
        })
        .collect();
    if invalid.is_empty() {
        return;
    }
    let plural = if invalid.len() == 1 { "" } else { "s" };
    sink.emit_span(
        RuleScope::Both,
        "S6328",
        &format!(
            "Referencing non-existing group{plural}: {}.",
            invalid.join(", ")
        ),
        replacement_span,
    );
}

/// Scans replacement-string text for group references; `$$` escapes are
/// skipped and numeric references take up to two digits, like JavaScript.
fn replacement_group_references(text: &str, parsed: &ParsedRegex) -> Vec<GroupReference> {
    let mut references = Vec::new();
    let mut i = 0;
    while let Some(relative) = text[i..].find('$') {
        i += relative;
        let (reference, consumed) = replacement_group_at(&text[i..], parsed);
        if let Some(reference) = reference {
            references.push(reference);
        }
        i += consumed;
    }
    references
}

fn replacement_group_at(candidate: &str, parsed: &ParsedRegex) -> (Option<GroupReference>, usize) {
    if candidate.as_bytes().get(1) == Some(&b'$') {
        return (None, 2);
    }
    if let Some(named) = named_group_at(candidate, parsed) {
        return named;
    }
    numeric_group_at(candidate, parsed.capture_count)
}

fn named_group_at(
    candidate: &str,
    parsed: &ParsedRegex,
) -> Option<(Option<GroupReference>, usize)> {
    (!parsed.capture_names.is_empty()).then_some(())?;
    let name_and_suffix = candidate.strip_prefix("$<")?;
    let close = name_and_suffix.find('>')?;
    (close > 0).then(|| {
        (
            Some(GroupReference::Name(name_and_suffix[..close].to_string())),
            close + 3,
        )
    })
}

fn numeric_group_at(candidate: &str, capture_count: usize) -> (Option<GroupReference>, usize) {
    let bytes = candidate.as_bytes();
    let digits = bytes[1..]
        .iter()
        .take_while(|byte| byte.is_ascii_digit())
        .count()
        .min(2);
    if digits == 0 {
        return (None, 1);
    }

    let first = u32::from(bytes[1] - b'0');
    let two = (digits == 2).then(|| first * 10 + u32::from(bytes[2] - b'0'));
    let captures = u32::try_from(capture_count).unwrap_or(u32::MAX);
    if let Some(index) = two.filter(|index| *index > 0 && *index <= captures) {
        return (Some(GroupReference::Index(index)), 3);
    }
    if first > 0 && first <= captures {
        return (Some(GroupReference::Index(first)), 2);
    }
    if first == 0 {
        // `$0` is literal. `$01` only becomes group 1 when that group exists,
        // handled by the two-digit branch above.
        return (None, digits + 1);
    }
    (
        Some(GroupReference::Index(two.unwrap_or(first))),
        digits + 1,
    )
}

fn reference_exists(reference: &GroupReference, parsed: &ParsedRegex) -> bool {
    match reference {
        GroupReference::Index(index) => {
            *index > 0 && u32::try_from(parsed.capture_count).is_ok_and(|count| *index <= count)
        }
        GroupReference::Name(name) => parsed.capture_names.iter().any(|known| known == name),
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn replacement_group_references_are_validated() {
        let out_of_range = js_keys("'ab'.replace(/(a)(b)/, '$3');\n");
        assert_eq!(count_key(&out_of_range, "javascript:S6328"), 1);

        let unknown_name = js_keys("'a'.replace(/(?<first>a)/, '$<second>');\n");
        assert_eq!(count_key(&unknown_name, "javascript:S6328"), 1);

        let clean = js_keys("'ab'.replace(/(a)(b)/, '$2$1');\n'a'.replace(/(?<x>a)/, '$<x>');\n");
        assert_eq!(count_key(&clean, "javascript:S6328"), 0);

        // `$$` escapes the dollar and never references a group.
        let escaped = js_keys("'ab'.replace(/(a)/, '$$1');\n");
        assert_eq!(count_key(&escaped, "javascript:S6328"), 0);

        // Two-digit references fall back to their valid first digit, while
        // `$0` is literal replacement text rather than a group reference.
        let fallback = js_keys(
            "'ab'.replace(/(a)(b)/, '$23');\n'a'.replace(/(a)/, '$10');\n'a'.replace(/(a)/, '$0');\n",
        );
        assert_eq!(count_key(&fallback, "javascript:S6328"), 0);
    }
}
