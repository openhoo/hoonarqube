use crate::AnalyzerOptions;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6538 / python:S6540 — missing annotations (opt-in) -----------------

pub(crate) fn check_missing_return_annotations(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    if !options.require_type_hints {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && function.returns.is_none()
        {
            issues.push(issue_at(
                "python:S6538",
                "Add a return type annotation to this function.",
                function.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}
