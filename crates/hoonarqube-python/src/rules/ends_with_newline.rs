use hoonarqube_ir::Issue;
use std::path::Path;

/// python:S113 — file must end with a newline character; empty files exempt.
pub(crate) fn check_ends_with_newline(path: &Path, source: &str) -> Vec<Issue> {
    if source.is_empty() || source.ends_with('\n') {
        return Vec::new();
    }
    let file_name = path.file_name().map_or_else(
        || path.display().to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    vec![Issue {
        rule_key: "python:S113".to_string(),
        message: format!("Add a new line at the end of this file \"{file_name}\"."),
        range: hoonarqube_ir::Range::file_level(),
        fix: None,
    }]
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

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
            "Add a new line at the end of this file \"t.py\"."
        );
        assert!(newline_issues[0].range.is_file_level());
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
