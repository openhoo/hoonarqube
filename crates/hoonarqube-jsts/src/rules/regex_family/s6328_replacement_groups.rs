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
    let invalid: Vec<String> = replacement_group_references(text)
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
pub(crate) fn replacement_group_references(text: &str) -> Vec<GroupReference> {
    let bytes = text.as_bytes();
    let mut references = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] != b'$' {
            i += 1;
            continue;
        }
        if bytes.get(i + 1) == Some(&b'$') {
            i += 2;
            continue;
        }
        if bytes.get(i + 1) == Some(&b'<')
            && let Some(close) = text[i + 2..].find('>')
        {
            let name = &text[i + 2..i + 2 + close];
            if !name.is_empty() {
                references.push(GroupReference::Name(name.to_string()));
                i += close + 3;
                continue;
            }
        }
        let digits = bytes[i + 1..]
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .count()
            .min(2);
        if digits > 0 {
            references.push(GroupReference::Index(
                text[i + 1..i + 1 + digits].parse().unwrap_or(u32::MAX),
            ));
            i += digits + 1;
            continue;
        }
        i += 1;
    }
    references
}

pub(crate) fn reference_exists(reference: &GroupReference, parsed: &ParsedRegex) -> bool {
    match reference {
        GroupReference::Index(index) => {
            *index > 0 && u32::try_from(parsed.capture_count).is_ok_and(|count| *index <= count)
        }
        GroupReference::Name(name) => parsed.capture_names.iter().any(|known| known == name),
    }
}
