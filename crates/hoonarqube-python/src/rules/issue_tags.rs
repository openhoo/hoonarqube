use crate::support::FIXME_TAG;
use crate::support::TODO_TAG;
use crate::support::comment_tokens;
use crate::support::has_person_reference;
use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

/// python:S1134/S1135/S1707 — track FIXME/TODO comments anchored at the
/// comment start (`#[ ]*fixme`, case-insensitively; `#\s*(?:TODO|todo|Todo)`
/// without a trailing word character, mirroring the upstream analyzers) and
/// require a person reference matching `[ ]*\([ _a-zA-Z0-9@.]+\)` right
/// after the tag.
pub(crate) fn check_issue_tags(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for comment in comment_tokens(parsed) {
        let raw = &source[comment.range()];
        let fixme_end = fixme_tag_end(raw);
        let todo_end = todo_tag_end(raw);
        let Some(tag_end) = fixme_end.or(todo_end) else {
            continue;
        };
        for (key, tag, end) in [
            ("python:S1134", FIXME_TAG, fixme_end),
            ("python:S1135", TODO_TAG, todo_end),
        ] {
            if end.is_some() {
                issues.push(Issue {
                    rule_key: key.to_string(),
                    message: format!(
                        "Resolve this {} comment or clarify it with a person reference.",
                        tag.to_uppercase()
                    ),
                    range: to_range(comment.range(), index, source),
                });
            }
        }
        if !has_person_reference(&raw[tag_end..]) {
            issues.push(Issue {
                rule_key: "python:S1707".to_string(),
                message: "Add a person reference such as '(jane)' to this TODO/FIXME comment."
                    .to_string(),
                range: to_range(comment.range(), index, source),
            });
        }
    }
    issues
}

/// End byte offset of an upstream RSPEC-1135 TODO tag anchored at the
/// comment start: `#\s*(?:TODO|todo|Todo)(?!\w)` — exactly these three
/// capitalizations, never followed by a word character.
fn todo_tag_end(raw: &str) -> Option<usize> {
    let after_hash = raw.strip_prefix('#')?;
    let body = after_hash.trim_start_matches(char::is_whitespace);
    for variant in ["TODO", "todo", "Todo"] {
        if let Some(rest) = body.strip_prefix(variant)
            && !rest.starts_with(|c: char| c.is_alphanumeric() || c == '_')
        {
            return Some(raw.len() - rest.len());
        }
    }
    None
}

/// End byte offset of an upstream RSPEC-1134 FIXME tag anchored at the
/// comment start: `#[ ]*fixme`, case-insensitively.
fn fixme_tag_end(raw: &str) -> Option<usize> {
    let after_hash = raw.strip_prefix('#')?;
    let body = after_hash.trim_start_matches(' ');
    if body.len() >= FIXME_TAG.len()
        && body.as_bytes()[..FIXME_TAG.len()].eq_ignore_ascii_case(FIXME_TAG.as_bytes())
    {
        return Some(raw.len() - body.len() + FIXME_TAG.len());
    }
    None
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::test_support::issue;
    use crate::{AnalyzerOptions, analyze};

    #[test]
    fn todo_and_fixme_tags_are_tracked_with_person_reference() {
        let report = analyze(
            PathBuf::from("t.py"),
            "# FIXME fix later\n# TODO (jane) improve\n",
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            report.issues,
            vec![
                issue(
                    "python:S1134",
                    "Resolve this FIXME comment or clarify it with a person reference.",
                    (1, 0),
                    (1, 17),
                ),
                issue(
                    "python:S1707",
                    "Add a person reference such as '(jane)' to this TODO/FIXME comment.",
                    (1, 0),
                    (1, 17),
                ),
                issue(
                    "python:S1135",
                    "Resolve this TODO comment or clarify it with a person reference.",
                    (2, 0),
                    (2, 21),
                ),
            ]
        );
    }

    #[test]
    fn unanchored_or_miscapitalized_tags_stay_silent() {
        let report = analyze(
            PathBuf::from("t.py"),
            "# todos pending\n# tOdO fix later\nvalue = 1  # AUTODOSING\n# see fixme notes\n",
            &AnalyzerOptions::default(),
        );
        // Judge only this module's emission surface: the shared analyzer
        // battery legitimately reports unrelated findings (e.g. python:S1481
        // for the unused local on line 3) that must not mask tag regressions.
        let tag_findings: Vec<_> = report
            .issues
            .iter()
            .filter(|finding| {
                matches!(
                    finding.rule_key.as_str(),
                    "python:S1134" | "python:S1135" | "python:S1707"
                )
            })
            .collect();
        assert!(tag_findings.is_empty(), "{tag_findings:?}");
    }

    #[test]
    fn anchored_todo_reports_s1135_and_s1707_without_person_reference() {
        let report = analyze(
            PathBuf::from("t.py"),
            "# todo: fix later\n",
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            report.issues,
            vec![
                issue(
                    "python:S1135",
                    "Resolve this TODO comment or clarify it with a person reference.",
                    (1, 0),
                    (1, 17),
                ),
                issue(
                    "python:S1707",
                    "Add a person reference such as '(jane)' to this TODO/FIXME comment.",
                    (1, 0),
                    (1, 17),
                ),
            ]
        );
    }

    #[test]
    fn anchored_fixme_matches_case_insensitively_without_required_space() {
        let report = analyze(
            PathBuf::from("t.py"),
            "#FixMe later\n",
            &AnalyzerOptions::default(),
        );
        assert_eq!(
            report.issues,
            vec![
                issue(
                    "python:S1134",
                    "Resolve this FIXME comment or clarify it with a person reference.",
                    (1, 0),
                    (1, 12),
                ),
                issue(
                    "python:S1707",
                    "Add a person reference such as '(jane)' to this TODO/FIXME comment.",
                    (1, 0),
                    (1, 12),
                ),
            ]
        );
    }
}
