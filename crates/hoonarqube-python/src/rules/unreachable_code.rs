use crate::engine::file_context::FileContext;
use crate::support::child_bodies;
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
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let scan = |suite: &[Stmt], issues: &mut Vec<Issue>| {
        for (position, stmt) in suite.iter().enumerate() {
            if is_jump_terminator(stmt) {
                for follower in &suite[position + 1..] {
                    issues.push(issue_at(
                        "python:S1763",
                        "Delete this unreachable code or refactor the code to make it reachable.",
                        follower.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    };
    scan(parsed.syntax().body.as_slice(), &mut issues);
    for stmt in &file_ctx.stmts {
        for body in child_bodies(stmt) {
            scan(body, &mut issues);
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s1763_flags_statements_after_terminator() {
        let flagged = scan("def f():\n    return 1\n    print(x)\n    y()\n");
        let found = findings(&flagged, "python:S1763");
        assert_eq!(found.len(), 2);
        assert_eq!(found[0].range.start.line, 3);
        assert_eq!(found[1].range.start.line, 4);
        let clean = "def f():\n    if a:\n        return 1\n    return 2\n";
        assert!(findings(&scan(clean), "python:S1763").is_empty());
    }
}
