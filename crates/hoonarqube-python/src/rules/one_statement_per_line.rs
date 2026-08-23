use crate::rules::suite::check_suite;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_one_statement_per_line(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    check_suite(parsed.syntax().body.as_slice(), &mut issues, index, source);
    issues
}
