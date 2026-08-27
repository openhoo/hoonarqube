use crate::support::comment_tokens;
use crate::support::noqa_format_valid;
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
        if !text.to_lowercase().contains("noqa") {
            continue;
        }
        issues.push(Issue {
            rule_key: "python:S1309".to_string(),
            message: "Do not suppress issues with a 'noqa' comment; fix the issue instead."
                .to_string(),
            range: to_range(comment.range(), index, source),
            fix: None,
        });
        if !noqa_format_valid(text) {
            issues.push(Issue {
                rule_key: "python:S7632".to_string(),
                message: "Use the format '# noqa: CODE' with comma-separated uppercase codes."
                    .to_string(),
                range: to_range(comment.range(), index, source),
                fix: None,
            });
        }
    }
    issues
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
            assert_eq!(report.issues.len(), 1, "source: {source}");
            assert_eq!(report.issues[0].rule_key, "python:S1309");
        }
        for source in ["#noqa", "# noqa : E501", "# noqa: e501"] {
            let report = analyze(
                PathBuf::from("t.py"),
                &format!("{source}\n"),
                &AnalyzerOptions::default(),
            );
            let keys: Vec<_> = report
                .issues
                .iter()
                .map(|issue| issue.rule_key.as_str())
                .collect();
            assert_eq!(
                keys,
                vec!["python:S1309", "python:S7632"],
                "source: {source}"
            );
        }
    }
}
