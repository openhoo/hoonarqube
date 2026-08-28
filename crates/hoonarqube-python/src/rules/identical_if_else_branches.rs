use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::ranges_textually_equal;
use crate::support::suite_span;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

// --- python:S3923 — identical `if`/`else` branches ---------------------------

pub(crate) fn check_identical_if_else_branches(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::If(if_stmt) = stmt else { continue };
        let [clause] = &if_stmt.elif_else_clauses[..] else {
            continue;
        };
        if clause.test.is_some()
            || !ranges_textually_equal(suite_span(&if_stmt.body), suite_span(&clause.body), source)
        {
            continue;
        }
        issues.push(issue_at(
            "python:S3923",
            "Remove this if statement or edit its code blocks so that they're not all the same.",
            TextRange::new(if_stmt.start(), if_stmt.start() + TextSize::new(2)),
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
    fn s3923_flags_identical_if_else_branches() {
        let flagged = scan("if a:\n    run()\nelse:\n    run()\n");
        assert_eq!(findings(&flagged, "python:S3923").len(), 1);
        let clean = "if a:\n    run()\nelse:\n    walk()\n";
        assert!(findings(&scan(clean), "python:S3923").is_empty());
    }
}
