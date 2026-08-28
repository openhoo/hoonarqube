use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::suite_can_break;
use crate::support::to_u32;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

// --- python:S2836 — loop `else` without `break` -----------------------------

pub(crate) fn check_loop_else_without_break(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let (body, orelse) = match stmt {
            Stmt::For(loop_stmt) => (&loop_stmt.body, &loop_stmt.orelse),
            Stmt::While(loop_stmt) => (&loop_stmt.body, &loop_stmt.orelse),
            _ => continue,
        };
        if orelse.is_empty() || suite_can_break(body) {
            continue;
        }
        let search_start = body.last().expect("non-empty loop body").end();
        let search_end = orelse.first().expect("non-empty else body").start();
        let between = &source[TextRange::new(search_start, search_end)];
        let Some(relative) = between.rfind("else") else {
            continue;
        };
        let keyword_start = search_start + TextSize::from(to_u32(relative));
        issues.push(issue_at(
            "python:S2836",
            "Add a \"break\" statement or remove this \"else\" clause.",
            TextRange::at(keyword_start, TextSize::new(4)),
            index,
            source,
        ));
    }
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
        assert_eq!(found[0].range.start.line, 3);
        let clean = "while x:\n    if done(x):\n        break\nelse:\n    close()\n";
        assert!(findings(&scan(clean), "python:S2836").is_empty());
    }

    #[test]
    fn s2836_flags_for_loop_else_and_return_bodies() {
        let flagged = scan("for item in items:\n    ship(item)\nelse:\n    close()\n");
        let found = findings(&flagged, "python:S2836");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);

        let returns = scan("while wait():\n    return None\nelse:\n    close()\n");
        assert_eq!(findings(&returns, "python:S2836").len(), 1);
    }

    #[test]
    fn s2836_allows_nested_conditional_breaks() {
        let clean = "for item in items:\n    if bad(item):\n        break\nelse:\n    close()\n";
        assert!(findings(&scan(clean), "python:S2836").is_empty());
    }
}
