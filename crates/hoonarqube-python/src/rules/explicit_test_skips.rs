use crate::support::constant_truth;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5918 — tests skipped through early returns ----------------------

pub(crate) fn check_explicit_test_skips(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::FunctionDef(function) = stmt else {
            return;
        };
        if !function.name.as_str().starts_with("test") || function.body.len() < 2 {
            return;
        }
        let Some(Stmt::If(guard)) = function.body.first() else {
            return;
        };
        let Some(Stmt::Return(last)) = guard.body.last() else {
            return;
        };
        if last.value.is_some() || constant_truth(&guard.test) == Some(false) {
            return;
        }
        issues.push(issue_at(
            "python:S5918",
            "Skip this test explicitly with the framework's skip mechanism instead of an early return.",
            guard.test.range(),
            index,
            source,
        ));
    });
    issues
}
