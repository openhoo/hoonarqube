use crate::support::visit_scopes_for_yields;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

// --- python:S2711 — yield/return outside a function ----------------------------

pub(crate) fn check_yield_return_outside_function(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_scopes_for_yields(
        parsed.syntax().body.as_slice(),
        0,
        &mut issues,
        index,
        source,
    );
    issues
}
