use crate::engine::file_context::FileContext;
use crate::support::comparison_pairs;
use crate::support::is_non_supporting_kind;
use crate::support::issue_at;
use crate::support::literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5642 — membership tests on unsupported operands ---------------------

pub(crate) fn check_s5642_membership_operands(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        if let Expr::Compare(compare) = expr {
            for (op, _, rhs) in comparison_pairs(compare) {
                let unsupported = matches!(
                    op,
                    ruff_python_ast::CmpOp::In | ruff_python_ast::CmpOp::NotIn
                ) && literal_kind(rhs).is_some_and(is_non_supporting_kind);
                if unsupported {
                    issues.push(issue_at(
                        "python:S5642",
                        "The right operand of this membership test does not support it.",
                        expr.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s5642_flags_membership_against_non_container_literals() {
        let bad = scan("present = 'x' in 42\n");
        assert_eq!(findings(&bad, "python:S5642").len(), 1);

        let good = scan("present = 'x' in ('x', 'y')\n");
        assert!(findings(&good, "python:S5642").is_empty());
    }
}
