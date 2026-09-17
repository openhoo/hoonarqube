use crate::support::comment_tokens;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S1309 — any `noqa` suppression comment is tracked.
/// python:S7632 — `noqa` comments must use `# noqa: CODE[,CODE...]` with
/// uppercase letter+digit codes.
pub(crate) fn check_noqa_comments(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for comment in comment_tokens(parsed) {
        let text = &source[comment.range()];
        let lower = text.to_lowercase();
        if !lower.contains("noqa") && !lower.contains("nosonar") && !lower.contains("nosec") {
            continue;
        }
        if lower.contains("noqa") {
            issues.push(Issue {
                rule_key: "python:S1309".to_string(),
                message: "Do not suppress issues with a 'noqa' comment; fix the issue instead."
                    .to_string(),
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


// --- python:S7632 — suppression-comment grammar --------------------------------
//
// Mirrors the reference's NoSonarInfoParser: a comment is split on `#` into
// inline pieces; each piece is checked as NOSONAR, noqa, or nosec.

fn is_invalid_suppression_comment(text: &str) -> bool {
    text.split('#')
        .filter(|piece| !piece.is_empty())
        .map(|piece| format!("#{piece}"))
        .any(|piece| {
            invalid_nosonar(&piece) || invalid_noqa(&piece) || invalid_nosec(&piece)
        })
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
    if rest.chars().next().is_some_and(|c| c.is_alphanumeric() || c == '_') {
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
            "# NOQA isort:skip",
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
