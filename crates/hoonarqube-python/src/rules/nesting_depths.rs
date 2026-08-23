use crate::AnalyzerOptions;
use crate::support::walk_nesting_depth;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

/// python:S134 — nesting depth of If/For/While/Try/With against
/// `maximumNestingDepth`.
pub(crate) fn check_nesting_depths(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_nesting_depth(
        parsed.syntax().body.as_slice(),
        0,
        options,
        &mut issues,
        index,
        source,
    );
    issues
}
