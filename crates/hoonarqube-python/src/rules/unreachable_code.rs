use crate::support::child_bodies;
use crate::support::for_each_stmt;
use crate::support::is_jump_terminator;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1763 — unreachable code -----------------------------------------

pub(crate) fn check_unreachable_code(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let scan = |suite: &[Stmt], issues: &mut Vec<Issue>| {
        for (position, stmt) in suite.iter().enumerate() {
            if is_jump_terminator(stmt) {
                for follower in &suite[position + 1..] {
                    issues.push(issue_at(
                        "python:S1763",
                        "This code is unreachable.",
                        follower.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    };
    scan(parsed.syntax().body.as_slice(), &mut issues);
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        for body in child_bodies(stmt) {
            scan(body, &mut issues);
        }
    });
    issues
}
