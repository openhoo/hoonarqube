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
            message: "Remove this usage of 'NOSONAR'.".to_string(),
            range: to_range(token.range(), index, source),
        })
        .collect()
}
