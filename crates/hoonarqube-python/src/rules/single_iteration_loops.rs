use crate::support::child_bodies;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_single_iteration_loops(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let body = match stmt {
            Stmt::For(loop_stmt) => &loop_stmt.body,
            Stmt::While(loop_stmt) => &loop_stmt.body,
            _ => return,
        };
        let Some(last) = body.last() else { return };
        if matches!(last, Stmt::Break(_)) && !suite_has_direct_continue(body) {
            issues.push(issue_at(
                "python:S1751",
                "This loop runs at most once; replace it with its body.",
                last.range(),
                index,
                source,
            ));
        }
    });
    issues
}

// --- migrated from support/mod.rs (S1751) ---
// --- python:S1751 — loops running at most once --------------------------------

fn suite_has_direct_continue(suite: &[Stmt]) -> bool {
    suite.iter().any(|stmt| match stmt {
        Stmt::Continue(_) => true,
        Stmt::For(_) | Stmt::While(_) | Stmt::FunctionDef(_) | Stmt::ClassDef(_) => false,
        _ => child_bodies(stmt)
            .iter()
            .any(|body| suite_has_direct_continue(body)),
    })
}
