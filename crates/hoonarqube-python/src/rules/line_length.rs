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
                    "This line exceeds the maximum allowed length of {} characters.",
                    options.maximum_line_length
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
        assert_eq!(report.issues.len(), 1);
        assert_eq!(report.issues[0].rule_key, "python:LineLength");
        assert_eq!(report.issues[0].range.start, pos(1, 0));
        assert_eq!(report.issues[0].range.end, pos(1, 121));

        let long_120 = format!("x = {}\nstr(x)\n", "1".repeat(116));
        let clean = analyze(
            PathBuf::from("test.py"),
            &long_120,
            &AnalyzerOptions::default(),
        );
        assert!(clean.issues.is_empty());

        let strict = AnalyzerOptions {
            maximum_line_length: 10,
            ..AnalyzerOptions::default()
        };
        let flagged = analyze(PathBuf::from("test.py"), "x = 12345678\nstr(x)\n", &strict);
        assert_eq!(flagged.issues.len(), 1);
        assert_eq!(
            flagged.issues[0].message,
            "This line exceeds the maximum allowed length of 10 characters."
        );
    }
}
