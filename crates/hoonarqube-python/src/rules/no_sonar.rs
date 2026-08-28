use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_no_sonar(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    parsed
        .tokens()
        .iter()
        .filter(|token| token.kind().is_comment())
        .filter(|token| source[token.range()].contains("NOSONAR"))
        .map(|token| Issue {
            rule_key: "python:NoSonar".to_string(),
            message: "Is #NOSONAR used to exclude false-positive or to hide real quality flaw?"
                .to_string(),
            range: to_range(token.range(), index, source),
            fix: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::test_support::issue;
    use crate::{AnalyzerOptions, analyze};

    #[test]
    fn nosonar_comment_is_flagged_case_sensitively() {
        let report = analyze(
            PathBuf::from("test.py"),
            "x = 1  # NOSONAR\nstr(x)\n",
            &AnalyzerOptions::default(),
        );
        let findings: Vec<_> = report
            .issues
            .into_iter()
            .filter(|issue| issue.rule_key == "python:NoSonar")
            .collect();
        assert_eq!(
            findings,
            vec![issue(
                "python:NoSonar",
                "Is #NOSONAR used to exclude false-positive or to hide real quality flaw?",
                (1, 7),
                (1, 16),
            )]
        );

        let lowercase = analyze(
            PathBuf::from("test.py"),
            "x = 1  # nosonar\nstr(x)\n",
            &AnalyzerOptions::default(),
        );
        assert!(
            lowercase
                .issues
                .iter()
                .all(|issue| issue.rule_key != "python:NoSonar")
        );
    }
}
