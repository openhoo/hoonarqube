use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::suite_can_break;
use crate::support::suite_span;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;

// --- python:S2836 — loop `else` without `break` -----------------------------

pub(crate) fn check_loop_else_without_break(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let (body, orelse) = match stmt {
            Stmt::For(loop_stmt) => (&loop_stmt.body, &loop_stmt.orelse),
            Stmt::While(loop_stmt) => (&loop_stmt.body, &loop_stmt.orelse),
            _ => return,
        };
        if orelse.is_empty() || suite_can_break(body) {
            return;
        }
        issues.push(issue_at(
            "python:S2836",
            "This 'else' only runs when the loop finishes without 'break'; remove it or add a 'break'.",
            suite_span(orelse),
            index,
            source,
        ));
    });
    issues
}
