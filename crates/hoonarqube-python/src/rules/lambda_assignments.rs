use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6661 — lambda assigned to a variable -----------------------------

pub(crate) fn check_lambda_assignments(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        match stmt {
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
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, pos, scan};
    use hoonarqube_ir::Range;

    const ASSIGNMENTS: [(&str, u32, u32); 6] = [
        ("handler = lambda event: str(event)\n", 1, 10),
        ("handler: object = lambda event: str(event)\n", 1, 18),
        ("first = second = lambda event: str(event)\n", 1, 17),
        (
            "handler = (\n    lambda event: (\n        str(event)\n    )\n)\n",
            2,
            4,
        ),
        ("é = lambda event: str(event)\n", 1, 4),
        (
            "self.is_allowed = lambda x: not fnmatch(x, disallow)\n",
            1,
            18,
        ),
    ];

    #[test]
    fn s6661_assignment_messages_match_reference() {
        for (source, _, _) in ASSIGNMENTS {
            let report = scan(source);
            let issues = findings(&report, "python:S6661");
            assert_eq!(issues.len(), 1, "{source}");
            assert_eq!(
                issues[0].message, "Define function instead of this lambda assignment statement.",
                "{source}"
            );
        }
    }

    #[test]
    fn s6661_primary_ranges_cover_only_the_lambda_keyword() {
        for (source, line, column) in ASSIGNMENTS {
            let report = scan(source);
            let issues = findings(&report, "python:S6661");
            assert_eq!(issues.len(), 1, "{source}");
            assert_eq!(
                issues[0].range,
                Range {
                    start: pos(line, column),
                    end: pos(line, column + 6),
                },
                "{source}"
            );
            assert!(issues[0].fix.is_none());
            assert!(issues[0].flows.is_empty());
            assert!(issues[0].alternatives.is_empty());
        }
    }

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
