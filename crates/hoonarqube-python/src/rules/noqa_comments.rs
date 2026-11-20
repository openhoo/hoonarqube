use crate::support::comment_tokens;
use crate::support::has_valid_legacy_syntax;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const NOQA_MESSAGE: &str = "Is 'noqa' used to exclude false-positive or to hide real quality flaw?";
const NOSEC_MESSAGE: &str =
    "Is 'nosec' used to exclude false-positive or to hide real security issue?";

/// python:S1309 — `noqa` and `nosec` suppression comments are tracked.
/// python:S7632 — `noqa` comments must use `# noqa: CODE[,CODE...]` with
/// uppercase letter+digit codes.
pub(crate) fn check_noqa_comments(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let valid_syntax = parsed.has_valid_syntax() || has_valid_legacy_syntax(parsed, source);
    for comment in comment_tokens(parsed) {
        let text = &source[comment.range()];
        let lower = text.to_lowercase();
        if !lower.contains("noqa") && !lower.contains("nosonar") && !lower.contains("nosec") {
            continue;
        }
        // Don't add nosec facts from invalid-source parser recovery. Retain
        // established noqa recovery behavior on those incomplete files.
        let message = if valid_syntax {
            tracking_message(text)
        } else {
            lower.contains("noqa").then_some(NOQA_MESSAGE)
        };
        if let Some(message) = message {
            issues.push(Issue {
                rule_key: "python:S1309".to_string(),
                message: message.to_string(),
                range: to_range(comment.range(), index, source),
                fix: None,
                flows: Vec::new(),
                alternatives: Vec::new(),
            });
        }
        if is_invalid_suppression_comment(text) {
            issues.push(Issue {
                rule_key: "python:S7632".to_string(),
                message: "Fix the syntax of this issue suppression comment.".to_string(),
                range: to_range(comment.range(), index, source),
                fix: None,
                flows: Vec::new(),
                alternatives: Vec::new(),
            });
        }
    }
    issues
}

fn tracking_message(text: &str) -> Option<&'static str> {
    // The reference selects the first valid inline directive, then reports on
    // the whole original comment. Java's default regex whitespace is ASCII.
    for piece in text.split('#') {
        let body = piece.trim_start_matches(reference_whitespace);
        if let Some(rest) = body.strip_prefix("noqa")
            && (rest.is_empty()
                || rest.starts_with(|ch| reference_whitespace(ch) || matches!(ch, ';' | ':')))
            && !rest.contains(['\u{0085}', '\u{2028}', '\u{2029}'])
        {
            return Some(NOQA_MESSAGE);
        }
        if body
            .get(..5)
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("nosec"))
        {
            let rest = &body[5..];
            // (?i)^#\s*nosec\b[:\s]*(.*): punctuation is a valid boundary,
            // and malformed rule arguments still belong to the separate S7632.
            if !rest.starts_with(|ch: char| ch.is_ascii_alphanumeric() || ch == '_')
                && !rest
                    .trim_start_matches(|ch| reference_whitespace(ch) || ch == ':')
                    .contains(['\n', '\r', '\u{0085}', '\u{2028}', '\u{2029}'])
            {
                return Some(NOSEC_MESSAGE);
            }
        }
    }
    None
}

fn reference_whitespace(ch: char) -> bool {
    matches!(ch, ' ' | '\t' | '\n' | '\r' | '\u{000b}' | '\u{000c}')
}

// --- python:S7632 — suppression-comment grammar --------------------------------
//
// Mirrors the reference's NoSonarInfoParser: a comment is split on `#` into
// inline pieces; each piece is checked as NOSONAR, noqa, or nosec.

fn is_invalid_suppression_comment(text: &str) -> bool {
    text.split('#')
        .filter(|piece| !piece.is_empty())
        .map(|piece| format!("#{piece}"))
        .any(|piece| invalid_nosonar(&piece) || invalid_noqa(&piece) || invalid_nosec(&piece))
}

/// `^#\s*NOSONAR(\W.*)?` prefix, then `^#\s*NOSONAR(?:\s*\(([^)]*)\))?($|\s.*)`
/// full match; parenthesized rules must match `^[a-zA-Z0-9]+$`.
fn invalid_nosonar(piece: &str) -> bool {
    let body = piece.trim_start_matches('#');
    let after_ws = body.trim_start();
    let Some(rest) = after_ws.strip_prefix("NOSONAR") else {
        // NOSONAR appearing without the `# NOSONAR` prefix is invalid.
        return piece.contains("NOSONAR");
    };
    // Prefix gate: the character after NOSONAR must be non-word (or end).
    if rest
        .chars()
        .next()
        .is_some_and(|c| c.is_alphanumeric() || c == '_')
    {
        return false;
    }
    // Full pattern: optional `\s*(rules)` then end or whitespace+text.
    let mut cursor = rest.trim_start();
    let mut rules: Option<&str> = None;
    if let Some(inner) = cursor.strip_prefix('(') {
        let Some(close) = inner.find(')') else {
            return true;
        };
        rules = Some(&inner[..close]);
        cursor = &inner[close + 1..];
    } else {
        cursor = rest;
    }
    if !(cursor.is_empty() || cursor.starts_with(char::is_whitespace)) {
        return true;
    }
    if let Some(rules) = rules {
        return rules
            .split(',')
            .map(str::trim)
            .any(|rule| !rule.is_empty() && !rule.chars().all(|c| c.is_ascii_alphanumeric()));
    }
    false
}

/// `#\s*noqa([\s:].*)?` prefix (full match), then
/// `^#\s*noqa(?::\s*(.+))?(?:[\s;:].*)?`; comma rules must be non-blank
/// and space-free.
fn invalid_noqa(piece: &str) -> bool {
    let body = piece.trim_start_matches('#');
    let after_ws = body.trim_start();
    let Some(rest) = after_ws.strip_prefix("noqa") else {
        return false;
    };
    // Prefix gate: after `noqa` only whitespace, `:`, or end.
    if !rest.is_empty() && !rest.starts_with([' ', '\t', ':']) {
        return false;
    }
    // Full pattern: optional `: rules` then `[\s;:]`-led trailing text.
    let Some(rules) = rest.trim_start().strip_prefix(':') else {
        return false;
    };
    let rules = rules.trim_start();
    if rules.is_empty() {
        return false;
    }
    let mut parts: Vec<&str> = rules.split(',').map(str::trim).collect();
    if let Some(last) = parts.last_mut() {
        *last = last.split([' ', '\t', ':']).next().unwrap_or(last).trim();
    }
    parts
        .iter()
        .any(|rule| rule.is_empty() || rule.contains(' '))
}

/// `(?i)^#\s*nosec\b[:\s]*(.*)`; with a comma list, every token must be a
/// `^[A-Za-z]\d+$` rule key or the comment is invalid.
fn invalid_nosec(piece: &str) -> bool {
    let lower = piece.to_lowercase();
    let Some(rest) = lower
        .trim_start_matches('#')
        .trim_start()
        .strip_prefix("nosec")
    else {
        return false;
    };
    if !rest.is_empty() && !rest.starts_with([' ', '\t', ':']) {
        return false;
    }
    let original_rest = &piece[piece.len() - rest.len()..];
    let rules = original_rest.trim_start_matches([' ', '\t', ':']);
    if rules.is_empty() || !rules.contains(',') {
        return false;
    }
    let mut parts: Vec<&str> = rules.split(',').map(str::trim).collect();
    if let Some(last) = parts.last_mut() {
        *last = last.split([' ', '\t', ':']).next().unwrap_or(last).trim();
    }
    let rule_keys = parts
        .iter()
        .filter(|rule| {
            rule.len() > 1
                && rule.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && rule[1..].chars().all(|c| c.is_ascii_digit())
        })
        .count();
    rule_keys > 0 && rule_keys != parts.len()
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::{AnalyzerOptions, analyze};

    #[test]
    fn noqa_requires_valid_lowercase_directive_in_complete_source() {
        for comment in ["# NOQA", "# noqax", "# mention noqa", "# NOQA isort:skip"] {
            let report = analyze(
                PathBuf::from("t.py"),
                &format!("value = 1 {comment}\n"),
                &AnalyzerOptions::default(),
            );
            assert!(
                report
                    .issues
                    .iter()
                    .all(|issue| issue.rule_key != "python:S1309"),
                "ordinary comment must not acquire S1309: {comment}"
            );
        }
    }

    #[test]
    fn noqa_comments_are_tracked_and_validated() {
        let well_formed = ["# noqa", "# noqa: E501", "# noqa: E501,F841"];
        for source in well_formed {
            let report = analyze(
                PathBuf::from("t.py"),
                &format!("{source}\n"),
                &AnalyzerOptions::default(),
            );
            let keys: Vec<_> = report
                .issues
                .iter()
                .filter_map(|issue| {
                    matches!(issue.rule_key.as_str(), "python:S1309" | "python:S7632")
                        .then_some(issue.rule_key.as_str())
                })
                .collect();
            assert_eq!(keys, vec!["python:S1309"], "source: {source}");
        }
        // The reference accepts `noqa` without a space, a space before the
        // colon, lowercase codes, and trailing text like `isort:skip`.
        for source in [
            "#noqa",
            "# noqa : E501",
            "# noqa: e501",
            "# noqa isort:skip",
        ] {
            let report = analyze(
                PathBuf::from("t.py"),
                &format!("{source}\n"),
                &AnalyzerOptions::default(),
            );
            let keys: Vec<_> = report
                .issues
                .iter()
                .filter(|issue| matches!(issue.rule_key.as_str(), "python:S1309" | "python:S7632"))
                .map(|issue| issue.rule_key.as_str())
                .collect();
            assert_eq!(keys, vec!["python:S1309"], "source: {source}");
        }
        // Malformed NOSONAR comments are what S7632 actually targets.
        for source in ["# NOSONAR(", "# NOSONAR(py rule)"] {
            let report = analyze(
                PathBuf::from("t.py"),
                &format!("x = 1  {source}\n"),
                &AnalyzerOptions::default(),
            );
            let keys: Vec<_> = report
                .issues
                .iter()
                .filter(|issue| issue.rule_key.as_str() == "python:S7632")
                .map(|issue| issue.rule_key.as_str())
                .collect();
            assert_eq!(keys, vec!["python:S7632"], "source: {source}");
        }
    }
}
