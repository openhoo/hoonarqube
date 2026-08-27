use crate::AnalyzerOptions;
use hoonarqube_ir::Issue;

pub(crate) fn check_license_header(options: &AnalyzerOptions, source: &str) -> Vec<Issue> {
    let format = options.copyright_header_format.as_str();
    if format.is_empty() {
        return Vec::new();
    }
    let body = source.strip_prefix("#!").map_or(source, |after_shebang| {
        after_shebang
            .split_once('\n')
            .map_or(after_shebang, |n| n.1)
    });
    let trimmed = body.trim_start_matches('\n');
    // Real-world headers are comments; accept an optional `#` marker plus
    // indentation between the format and the file head.
    let unmarked = trimmed
        .strip_prefix('#')
        .map_or(trimmed, |rest| rest.trim_start_matches([' ', '\t']));
    if trimmed.starts_with(format) || unmarked.starts_with(format) {
        return Vec::new();
    }
    vec![Issue {
        rule_key: "python:S1451".to_string(),
        message: "Add or update the copyright header of this file.".to_string(),
        range: hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos { line: 1, column: 0 },
            end: hoonarqube_ir::Pos { line: 1, column: 0 },
        },
        fix: None,
    }]
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::test_support::issue;
    use crate::{AnalyzerOptions, analyze};

    #[test]
    fn license_header_is_enforced_only_when_configured() {
        let options = AnalyzerOptions {
            copyright_header_format: "Copyright 2026".to_string(),
            ..AnalyzerOptions::default()
        };
        assert!(
            analyze(
                PathBuf::from("t.py"),
                "# Copyright 2026\nfor _ in []:\n    _ = None\n",
                &options
            )
            .issues
            .is_empty()
        );
        assert!(
            analyze(
                PathBuf::from("t.py"),
                "#!/usr/bin/env python3\n# Copyright 2026\nfor _ in []:\n    _ = None\n",
                &options
            )
            .issues
            .is_empty()
        );
        let missing = analyze(
            PathBuf::from("t.py"),
            "for _ in []:\n    _ = None\n",
            &options,
        );
        assert_eq!(
            missing.issues,
            vec![issue(
                "python:S1451",
                "Add or update the copyright header of this file.",
                (1, 0),
                (1, 0)
            )]
        );
        assert!(
            analyze(
                PathBuf::from("t.py"),
                "for _ in []:\n    _ = None\n",
                &AnalyzerOptions::default()
            )
            .issues
            .is_empty()
        );
    }
}
