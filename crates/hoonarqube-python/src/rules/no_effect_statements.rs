use crate::support::visit_suites_for_no_effect;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

// --- python:S905 — statements without effect ----------------------------------

pub(crate) fn check_no_effect_statements(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_suites_for_no_effect(parsed.syntax().body.as_slice(), &mut issues, index, source);
    issues
}
