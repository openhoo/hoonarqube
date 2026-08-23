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
    }]
}
