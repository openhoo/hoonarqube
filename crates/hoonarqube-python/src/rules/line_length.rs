use crate::AnalyzerOptions;
use crate::support::to_u32;
use hoonarqube_ir::Issue;

pub(crate) fn check_line_length(source: &str, options: &AnalyzerOptions) -> Vec<Issue> {
    let maximum = usize::try_from(options.maximum_line_length).unwrap_or(usize::MAX);
    let mut issues = Vec::new();
    for (zero_based, chunk) in source.split_inclusive('\n').enumerate() {
        let line = chunk.trim_end_matches(['\r', '\n']);
        let length = line.chars().count();
        if length > maximum {
            let line_number = to_u32(zero_based) + 1;
            issues.push(Issue {
                rule_key: "python:LineLength".to_string(),
                message: format!(
                    "The line contains {length} characters which is greater than {} authorized.",
                    options.maximum_line_length,
                ),
                range: hoonarqube_ir::Range {
                    start: hoonarqube_ir::Pos {
                        line: line_number,
                        column: 0,
                    },
                    end: hoonarqube_ir::Pos {
                        line: line_number,
                        column: to_u32(length),
                    },
                },
                fix: None,
                flows: Vec::new(),
            });
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use std::path::PathBuf;

    use crate::test_support::pos;
    use crate::{AnalyzerOptions, analyze};

    #[test]
    fn line_length_honors_option() {
        let long_121 = format!("x = {}\nstr(x)\n", "1".repeat(117));
        // 4 + 117 content characters on line 1, plus a short reader line.
        assert_eq!(
            long_121.lines().next().map(str::chars).map(Iterator::count),
            Some(121)
        );
        let report = analyze(
            PathBuf::from("test.py"),
            &long_121,
            &AnalyzerOptions::default(),
        );
        let findings: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "python:LineLength")
            .collect();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].range.start, pos(1, 0));
        assert_eq!(findings[0].range.end, pos(1, 121));

        let long_120 = format!("x = {}\nstr(x)\n", "1".repeat(116));
        let clean = analyze(
            PathBuf::from("test.py"),
            &long_120,
            &AnalyzerOptions::default(),
        );
        assert!(
            clean
                .issues
                .iter()
                .all(|issue| issue.rule_key != "python:LineLength")
        );

        let strict = AnalyzerOptions {
            maximum_line_length: 10,
            ..AnalyzerOptions::default()
        };
        let flagged = analyze(PathBuf::from("test.py"), "x = 12345678\nstr(x)\n", &strict);
        let flagged: Vec<_> = flagged
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "python:LineLength")
            .collect();
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "The line contains 12 characters which is greater than 10 authorized."
        );
    }
}
