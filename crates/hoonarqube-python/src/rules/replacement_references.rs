use crate::engine::rx::RegexSite;
use crate::engine::rx::RxParsed;
use crate::engine::rx::RxUnit;
use crate::engine::rx::parse_regex;
use crate::support::issue_at;
use crate::support::to_u32;
use hoonarqube_ir::Issue;
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;
use ruff_text_size::TextSize;

/// python:S6328 — `re.sub`/`re.subn` replacement strings must reference
/// groups that exist in the pattern.
pub(crate) fn check_replacement_references(
    site: &RegexSite,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let (Some(units), Some(repl)) = (&site.pattern, &site.repl) else {
        return;
    };
    let Ok(parsed) = parse_regex(units) else {
        return;
    };
    let mut position = 0;
    while position < repl.units.len() {
        if repl.units[position].ch != '\\' {
            position += 1;
            continue;
        }
        let Some(back) = repl.units.get(position + 1) else {
            break;
        };
        match back.ch {
            'g' => {
                position =
                    check_named_reference(&parsed, &repl.units, position, index, source, issues);
            }
            '0'..='9' => {
                position += check_numeric_reference(
                    back,
                    &repl.units[position + 1..],
                    parsed.capture_count,
                    index,
                    source,
                    issues,
                );
            }
            _ => position += 1,
        }
    }
}

/// Validates a `\g<name|digits>` reference; returns the next scan position.
fn check_named_reference(
    parsed: &RxParsed,
    units: &[RxUnit],
    slash: usize,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) -> usize {
    let mut cursor = slash + 2;
    if units.get(cursor).map(|u| u.ch) != Some('<') {
        return slash + 1;
    }
    cursor += 1;
    let start = cursor;
    let Some(close) = units[start..].iter().position(|u| u.ch == '>') else {
        return slash + 1;
    };
    let body: String = units[start..start + close].iter().map(|u| u.ch).collect();
    let span = TextRange::new(units[start].at, units[start + close].at);
    let invalid = if body.chars().all(|c| c.is_ascii_digit()) && !body.is_empty() {
        // Python parses group numbers with arbitrary precision, so a
        // reference too large for u32 can never match a real group either.
        body.parse::<u32>()
            .map_or(true, |number| number > parsed.capture_count)
    } else {
        !parsed.names.iter().any(|name| name == &body)
    };
    if invalid {
        issues.push(issue_at(
            "python:S6328",
            "Reference an existing group in this replacement string.",
            span,
            index,
            source,
        ));
    }
    start + close + 1
}

/// Validates a `\N` group reference against the capture count; returns how
/// many units the escape consumed.
fn check_numeric_reference(
    back: &RxUnit,
    rest: &[RxUnit],
    capture_count: u32,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) -> usize {
    let digits: String = rest
        .iter()
        .take(2)
        .take_while(|u| u.ch.is_ascii_digit())
        .map(|u| u.ch)
        .collect();
    let span = TextRange::new(
        back.at,
        back.at + TextSize::from(to_u32(digits.len().max(1))),
    );
    if let Ok(number) = digits.parse::<u32>()
        && number != 0
        && number > capture_count
    {
        issues.push(issue_at(
            "python:S6328",
            "Reference an existing group in this replacement string.",
            span,
            index,
            source,
        ));
    }
    1 + digits.len()
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings_of, regex_finds};

    #[test]
    fn s6328_validates_group_references_in_replacements() {
        let flagged = "import re\nre.sub(r'(a)(b)(c)', r'\\1, \\9, \\3', s)\n";
        assert_eq!(findings_of(flagged, "python:S6328").len(), 1);
        assert!(!regex_finds(
            "import re\nre.sub(r'(a)(b)(c)', r'\\1, \\2, \\3', s)\n",
            "python:S6328"
        ));
        assert!(regex_finds(
            "import re\nre.sub(r'(?P<a>x)', r'\\g<b>', s)\n",
            "python:S6328"
        ));
    }

    #[test]
    fn s6328_flags_overflowing_numeric_group_references() {
        assert!(regex_finds(
            "import re\nre.sub('()', r'\\g<99999999999999>', s)\n",
            "python:S6328"
        ));
        assert!(regex_finds(
            "import re\nre.sub(r'(a)(b)(c)', r'\\g<4294967296>', s)\n",
            "python:S6328"
        ));
        assert!(!regex_finds(
            "import re\nre.sub(r'(a)(b)(c)', r'\\g<2>', s)\n",
            "python:S6328"
        ));
    }
}
