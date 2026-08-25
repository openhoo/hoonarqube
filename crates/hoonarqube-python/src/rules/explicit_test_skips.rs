use crate::engine::file_context::FileContext;
use crate::support::constant_truth;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5918 — tests skipped through early returns ----------------------

pub(crate) fn check_explicit_test_skips(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::FunctionDef(function) = stmt else {
            continue;
        };
        if !function.name.as_str().starts_with("test") || function.body.len() < 2 {
            continue;
        }
        let Some(Stmt::If(guard)) = function.body.first() else {
            continue;
        };
        let Some(Stmt::Return(last)) = guard.body.last() else {
            continue;
        };
        if last.value.is_some() || constant_truth(&guard.test) == Some(false) {
            continue;
        }
        issues.push(issue_at(
            "python:S5918",
            "Skip this test explicitly with the framework's skip mechanism instead of an early return.",
            guard.test.range(),
            index,
            source,
        ));
    }
    issues
}
