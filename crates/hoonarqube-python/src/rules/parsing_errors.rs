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
            message: format!("{}", error.error),
            range: to_range(error.location, index, source),
        })
        .collect()
}
