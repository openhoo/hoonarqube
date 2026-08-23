use crate::support::for_each_stmt;
use crate::support::function_parameters;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7483 — timeout parameter on an async function ---------------------

pub(crate) fn check_async_timeout_parameters(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::FunctionDef(function) = stmt
            && function.is_async
        {
            for parameter in function_parameters(function) {
                if parameter.parameter.name.as_str().starts_with("timeout") {
                    issues.push(issue_at(
                        "python:S7483",
                        "Remove the timeout parameter from this async function.",
                        parameter.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    });
    issues
}
