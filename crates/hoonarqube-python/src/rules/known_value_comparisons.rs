use crate::support::scan_known_value_suite;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use std::collections::HashMap;

pub(crate) fn check_known_value_comparisons(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    scan_known_value_suite(
        parsed.syntax().body.as_slice(),
        &HashMap::new(),
        index,
        source,
        &mut issues,
    );
    issues
}
