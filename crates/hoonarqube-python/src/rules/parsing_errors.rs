use crate::support::to_range;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use std::fmt::Write as _;

pub(crate) fn check_parsing_errors(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let Some(error) = parsed
        .errors()
        .iter()
        .min_by_key(|error| error.location.start())
    else {
        return Vec::new();
    };
    let location = to_range(error.location, index, source);
    let line_number = location.start.line;
    let column = location.start.column;
    let lines: Vec<&str> = source.lines().collect();
    let line_index = usize::try_from(line_number.saturating_sub(1)).unwrap_or(usize::MAX);
    let Some(error_line) = lines.get(line_index) else {
        return Vec::new();
    };
    let mut excerpt = format!("  -->  {error_line}");
    for (offset, line) in lines.iter().skip(line_index + 1).enumerate() {
        let number = line_number + u32::try_from(offset).unwrap_or(u32::MAX) + 1;
        write!(excerpt, "\n    {number}: {line}").expect("writing to String cannot fail");
    }
    write!(excerpt, "\n    {}: EOF", lines.len() + 1).expect("writing to String cannot fail");
    vec![Issue {
        rule_key: "python:ParsingError".to_string(),
        message: format!("Parse error at line {line_number} column {column}:\n\n{excerpt}"),
        range: hoonarqube_ir::Range {
            start: hoonarqube_ir::Pos {
                line: line_number,
                column: 0,
            },
            end: hoonarqube_ir::Pos {
                line: line_number,
                column: u32::try_from(error_line.chars().count()).unwrap_or(u32::MAX),
            },
        },
        fix: None,
    }]
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
        assert_eq!(parsing.len(), 1);
        assert!(
            parsing[0]
                .message
                .starts_with("Parse error at line 1 column 6:")
        );
    }
}
