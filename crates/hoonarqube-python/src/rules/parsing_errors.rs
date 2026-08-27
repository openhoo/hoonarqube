use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_parsing_errors(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    parsed
        .errors()
        .iter()
        .map(|error| Issue {
            rule_key: "python:ParsingError".to_string(),
            message: format!("Fix this syntax error: {error}."),
            range: to_range(error.location, index, source),
            fix: None,
        })
        .collect()
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::{AnalyzerOptions, analyze};

    #[test]
    fn parsing_errors_are_recovered_from_tolerantly() {
        let report = analyze(
            PathBuf::from("test.py"),
            "def f(:\n    pass",
            &AnalyzerOptions::default(),
        );
        let parsing: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "python:ParsingError")
            .collect();
        // Ruff 0.0.10 tolerant recovery emits exactly these two errors for
        // this input; the analyzer reports one issue per `errors()` entry.
        assert_eq!(parsing.len(), 2);
        assert!(parsing[0].message.contains("Expected"));
        assert!(parsing[0].message.starts_with("Fix this syntax error: "));
    }
}
