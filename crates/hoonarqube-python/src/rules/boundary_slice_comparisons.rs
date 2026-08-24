use crate::support::for_each_stmt_expr;
use crate::support::is_boundary_slice;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6659 — startswith/endswith over slicing --------------------------

pub(crate) fn check_boundary_slice_comparisons(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Compare(compare) = expr else { return };
        if !compare.ops.iter().any(|op| {
            matches!(
                op,
                ruff_python_ast::CmpOp::Eq
                    | ruff_python_ast::CmpOp::NotEq
                    | ruff_python_ast::CmpOp::Is
                    | ruff_python_ast::CmpOp::IsNot
            )
        }) {
            return;
        }
        let mut sides: Vec<&Expr> = vec![&compare.left];
        sides.extend(&compare.comparators);
        let flagged = sides.iter().any(|side| {
            is_boundary_slice(side)
                && sides.iter().any(|other| {
                    !std::ptr::eq(*side, *other) && matches!(other, Expr::StringLiteral(_))
                })
        });
        if flagged {
            issues.push(issue_at(
                "python:S6659",
                "Use 'startswith' or 'endswith' for this prefix or suffix comparison.",
                compare.range(),
                index,
                source,
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6659_prefers_startswith_endswith_over_slices() {
        assert_eq!(
            findings(&scan("head = name[:2] == \"ab\"\n"), "python:S6659").len(),
            1
        );
        assert_eq!(
            findings(&scan("tail = name[-2:] == \"cd\"\n"), "python:S6659").len(),
            1
        );
        assert!(findings(&scan("mid = name[1:2] == \"b\"\n"), "python:S6659").is_empty());
    }
}
