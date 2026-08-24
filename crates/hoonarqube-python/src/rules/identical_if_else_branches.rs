use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::ranges_textually_equal;
use crate::support::suite_span;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S3923 — identical `if`/`else` branches ---------------------------

pub(crate) fn check_identical_if_else_branches(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::If(if_stmt) = stmt else { return };
        let [clause] = &if_stmt.elif_else_clauses[..] else {
            return;
        };
        if clause.test.is_some()
            || !ranges_textually_equal(suite_span(&if_stmt.body), suite_span(&clause.body), source)
        {
            return;
        }
        issues.push(issue_at(
            "python:S3923",
            "Either merge this branch with the identical one or change one of the implementations.",
            if_stmt.range(),
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
    fn s3923_flags_identical_if_else_branches() {
        let flagged = scan("if a:\n    run()\nelse:\n    run()\n");
        assert_eq!(findings(&flagged, "python:S3923").len(), 1);
        let clean = "if a:\n    run()\nelse:\n    walk()\n";
        assert!(findings(&scan(clean), "python:S3923").is_empty());
    }
}
