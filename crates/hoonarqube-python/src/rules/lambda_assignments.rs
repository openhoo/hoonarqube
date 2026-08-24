use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6661 — lambda assigned to a variable -----------------------------

pub(crate) fn check_lambda_assignments(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| match stmt {
        Stmt::Assign(assign) => {
            if let Expr::Lambda(lambda) = assign.value.as_ref() {
                issues.push(issue_at(
                    "python:S6661",
                    "Replace this assigned lambda with a 'def' statement.",
                    lambda.range(),
                    index,
                    source,
                ));
            }
        }
        Stmt::AnnAssign(annotated) => {
            if let Some(Expr::Lambda(lambda)) = annotated.value.as_deref() {
                issues.push(issue_at(
                    "python:S6661",
                    "Replace this assigned lambda with a 'def' statement.",
                    lambda.range(),
                    index,
                    source,
                ));
            }
        }
        _ => {}
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6661_flags_lambdas_assigned_to_names() {
        assert_eq!(
            findings(&scan("handler = lambda e: str(e)\n"), "python:S6661").len(),
            1
        );
        assert!(
            findings(
                &scan("def handler(e):\n    return str(e)\n"),
                "python:S6661"
            )
            .is_empty()
        );
    }
}
