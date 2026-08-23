use crate::engine::rx::RegexSite;
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
                let mut cursor = position + 2;
                if repl.units.get(cursor).map(|u| u.ch) != Some('<') {
                    position += 1;
                    continue;
                }
                cursor += 1;
                let start = cursor;
                let digits_or_name = |units: &[RxUnit], from: usize| -> Option<usize> {
                    units[from..].iter().position(|u| u.ch == '>')
                };
                if let Some(close) = digits_or_name(&repl.units, start) {
                    let body: String = repl.units[start..start + close]
                        .iter()
                        .map(|u| u.ch)
                        .collect();
                    let span = TextRange::new(repl.units[start].at, repl.units[start + close].at);
                    let invalid = if body.chars().all(|c| c.is_ascii_digit()) && !body.is_empty() {
                        body.parse::<u32>()
                            .is_ok_and(|number| number > parsed.capture_count)
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
                    position = start + close + 1;
                    continue;
                }
                position += 1;
            }
            '0'..='9' => {
                let digits: String = repl.units[position + 1..]
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
                    && number > parsed.capture_count
                {
                    issues.push(issue_at(
                        "python:S6328",
                        "Reference an existing group in this replacement string.",
                        span,
                        index,
                        source,
                    ));
                }
                position += 1 + digits.len();
            }
            _ => position += 1,
        }
    }
}
