use crate::support::exprs_textually_equal;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1862 — identical conditions in an if/elif chain -----------------

pub(crate) fn check_duplicate_conditions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::If(if_stmt) = stmt else { return };
        let mut previous: Vec<&Expr> = vec![&if_stmt.test];
        for clause in &if_stmt.elif_else_clauses {
            let Some(test) = clause.test.as_ref() else {
                break;
            };
            if previous
                .iter()
                .any(|earlier| exprs_textually_equal(earlier, test, source))
            {
                issues.push(issue_at(
                    "python:S1862",
                    "This condition duplicates an earlier one; this branch can never run.",
                    test.range(),
                    index,
                    source,
                ));
            }
            previous.push(test);
        }
    });
    issues
}
