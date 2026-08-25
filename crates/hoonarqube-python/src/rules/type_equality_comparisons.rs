use crate::engine::file_context::FileContext;
use crate::support::is_type_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6660 — `type()` equality instead of isinstance -------------------

pub(crate) fn check_type_equality_comparisons(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Compare(compare) = expr else {
            continue;
        };
        if !compare.ops.iter().any(|op| {
            matches!(
                op,
                ruff_python_ast::CmpOp::Eq
                    | ruff_python_ast::CmpOp::NotEq
                    | ruff_python_ast::CmpOp::Is
                    | ruff_python_ast::CmpOp::IsNot
            )
        }) {
            continue;
        }
        let mut sides: Vec<&Expr> = vec![&compare.left];
        sides.extend(&compare.comparators);
        let flagged = sides.iter().any(|side| {
            is_type_call(side)
                && sides.iter().any(|other| {
                    !std::ptr::eq(*side, *other)
                        && matches!(other, Expr::Name(_) | Expr::Attribute(_))
                })
        });
        if flagged {
            issues.push(issue_at(
                "python:S6660",
                "Use 'isinstance' instead of comparing the result of 'type()' directly.",
                compare.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s6660_prefers_isinstance_over_type_equality() {
        assert_eq!(
            findings(&scan("exact = type(x) is int\n"), "python:S6660").len(),
            1
        );
        assert!(findings(&scan("safe = isinstance(x, int)\n"), "python:S6660").is_empty());
    }
}
