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

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s2836_flags_loop_else_without_break() {
        let flagged = scan("while x:\n    drain()\nelse:\n    close()\n");
        let found = findings(&flagged, "python:S2836");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 4);
        let clean = "while x:\n    if done(x):\n        break\nelse:\n    close()\n";
        assert!(findings(&scan(clean), "python:S2836").is_empty());
    }

    #[test]
    fn s2836_flags_for_loop_else_and_return_bodies() {
        let flagged = scan("for item in items:\n    ship(item)\nelse:\n    close()\n");
        let found = findings(&flagged, "python:S2836");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 4);

        let returns = scan("while wait():\n    return None\nelse:\n    close()\n");
        assert_eq!(findings(&returns, "python:S2836").len(), 1);
    }

    #[test]
    fn s2836_allows_nested_conditional_breaks() {
        let clean = "for item in items:\n    if bad(item):\n        break\nelse:\n    close()\n";
        assert!(findings(&scan(clean), "python:S2836").is_empty());
    }
}
