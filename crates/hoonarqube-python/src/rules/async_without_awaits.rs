use crate::support::async_features_present;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_async_without_awaits(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && function.is_async
            && !async_features_present(function)
        {
            issues.push(issue_at(
                "python:S7503",
                "This async function never awaits; make it synchronous or await something.",
                function.name.range(),
                index,
                source,
            ));
        }
    });
    issues
}
