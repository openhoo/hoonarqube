use crate::engine::file_context::FileContext;
use crate::support::exprs_textually_equal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1862 — identical conditions in an if/elif chain -----------------

pub(crate) fn check_duplicate_conditions(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::If(if_stmt) = stmt else { continue };
        let mut previous: Vec<&Expr> = vec![&if_stmt.test];
        for clause in &if_stmt.elif_else_clauses {
            let Some(test) = clause.test.as_ref() else {
                break;
            };
            if let Some(earlier) = previous
                .iter()
                .find(|earlier| exprs_textually_equal(earlier, test, source))
            {
                let earlier_line = index.line_column(earlier.start(), source).line.get();
                issues.push(issue_at(
                    "python:S1862",
                    &format!("This branch duplicates the one on line {earlier_line}."),
                    test.range(),
                    index,
                    source,
                ));
            }
            previous.push(test);
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s1862_flags_duplicate_conditions_in_chain() {
        let flagged = scan("if a == 1:\n    f()\nelif a == 1:\n    g()\n");
        let found = findings(&flagged, "python:S1862");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
        let clean = "if a == 1:\n    f()\nelif a == 2:\n    g()\n";
        assert!(findings(&scan(clean), "python:S1862").is_empty());
    }
}
