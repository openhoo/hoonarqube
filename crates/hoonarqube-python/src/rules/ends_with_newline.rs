use crate::support::to_u32;
use hoonarqube_ir::Issue;

/// python:S113 — file must end with a newline character; empty files exempt.
pub(crate) fn check_ends_with_newline(source: &str) -> Vec<Issue> {
    if source.is_empty() || source.ends_with('\n') {
        return Vec::new();
    }
    let last_line = to_u32(source.split_inclusive('\n').count());
    let length = source.split_inclusive('\n').next_back().map_or(0, |chunk| {
        to_u32(chunk.trim_end_matches('\r').chars().count())
    });
    vec![Issue {
        rule_key: "python:S113".to_string(),
        message: "Add a newline character at the end of this file.".to_string(),
        range: hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos {
                line: last_line,
                column: 0,
            },
            end: hoonarqube_ir::Pos {
                line: last_line,
                column: length,
            },
        },
        fix: None,
    }]
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::test_support::pos;
    use crate::{AnalyzerOptions, analyze};

    #[test]
    fn file_must_end_with_newline() {
        let missing = analyze(PathBuf::from("t.py"), "x = 1", &AnalyzerOptions::default());
        let newline_issues: Vec<_> = missing
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "python:S113")
            .collect();
        assert_eq!(newline_issues.len(), 1);
        assert_eq!(
            newline_issues[0].message,
            "Add a newline character at the end of this file."
        );
        assert_eq!(newline_issues[0].range.start, pos(1, 0));
        assert_eq!(newline_issues[0].range.end, pos(1, 5));
        assert!(
            analyze(PathBuf::from("t.py"), "", &AnalyzerOptions::default())
                .issues
                .iter()
                .all(|issue| issue.rule_key != "python:S113")
        );
        assert!(
            analyze(
                PathBuf::from("t.py"),
                "x = 1\n",
                &AnalyzerOptions::default()
            )
            .issues
            .iter()
            .all(|issue| issue.rule_key != "python:S113")
        );
    }
}
