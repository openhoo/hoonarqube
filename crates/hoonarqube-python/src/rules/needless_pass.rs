use crate::engine::scope::SuiteOwner;
use crate::support::visit_suites_for_pass;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

pub(crate) fn check_needless_pass(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    visit_suites_for_pass(
        parsed.syntax().body.as_slice(),
        SuiteOwner::Module,
        &mut issues,
        index,
        source,
    );
    issues
}
