use crate::support::exprs_textually_equal;
use crate::support::for_each_stmt;
use crate::support::is_assignable_shape;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1656 — self-assignment ------------------------------------------

pub(crate) fn check_self_assignment(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| match stmt {
        Stmt::Assign(assign) => {
            if assign.targets.iter().any(|target| {
                is_assignable_shape(target) && exprs_textually_equal(target, &assign.value, source)
            }) {
                issues.push(issue_at(
                    "python:S1656",
                    "Remove this self-assignment.",
                    assign.range(),
                    index,
                    source,
                ));
            }
        }
        Stmt::AnnAssign(annotated) => {
            if let Some(value) = annotated.value.as_deref()
                && is_assignable_shape(&annotated.target)
                && exprs_textually_equal(&annotated.target, value, source)
            {
                issues.push(issue_at(
                    "python:S1656",
                    "Remove this self-assignment.",
                    annotated.range(),
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
    fn s1656_flags_self_assignment() {
        assert_eq!(findings(&scan("x = x\n"), "python:S1656").len(), 1);
        assert_eq!(findings(&scan("x.y = x.y\n"), "python:S1656").len(), 1);
        assert!(findings(&scan("x = y\n"), "python:S1656").is_empty());
    }
}
