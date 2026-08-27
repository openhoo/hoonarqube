use crate::support::for_each_line;
use crate::support::to_u32;
use hoonarqube_ir::Issue;

/// python:S1131 — lines must not end with whitespace.
pub(crate) fn check_trailing_whitespace(source: &str) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_line(source, |line, text| {
        let content = text.trim_end_matches([' ', '\t']);
        if content.len() < text.len() {
            issues.push(Issue {
                rule_key: "python:S1131".to_string(),
                message: "Remove the trailing whitespaces from this line.".to_string(),
                range: hoonarqube_ir::Range {
                    start: hoonarqube_ir::Pos {
                        line,
                        column: to_u32(content.chars().count()),
                    },
                    end: hoonarqube_ir::Pos {
                        line,
                        column: to_u32(text.chars().count()),
                    },
                },
                fix: None,
            });
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::test_support::pos;
    use crate::{AnalyzerOptions, analyze};

    #[test]
    fn trailing_whitespace_is_flagged_per_line() {
        let report = analyze(
            PathBuf::from("t.py"),
            "a \nb\t\nc\n",
            &AnalyzerOptions::default(),
        );
        let flagged: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "python:S1131")
            .collect();
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start, pos(1, 1));
        assert_eq!(flagged[0].range.end, pos(1, 2));
        assert_eq!(flagged[1].range.start, pos(2, 1));
        assert_eq!(flagged[1].range.end, pos(2, 2));
    }
}
