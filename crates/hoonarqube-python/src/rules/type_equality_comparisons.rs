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
        // Sonar's DirectTypeComparisonCheck evaluates each operand pair of
        // a comparison chain and only handles ==/!= — `is`/`is not`
        // identity legs stay silent.
        let mut operands: Vec<&Expr> = vec![&compare.left];
        operands.extend(&compare.comparators);
        let flagged = compare.ops.iter().enumerate().any(|(i, op)| {
            matches!(
                op,
                ruff_python_ast::CmpOp::Eq | ruff_python_ast::CmpOp::NotEq
            ) && (is_type_call(operands[i])
                && matches!(operands[i + 1], Expr::Name(_) | Expr::Attribute(_))
                || is_type_call(operands[i + 1])
                    && matches!(operands[i], Expr::Name(_) | Expr::Attribute(_)))
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
            findings(&scan("exact = type(x) == int\n"), "python:S6660").len(),
            1
        );
        assert_eq!(
            findings(&scan("exact = type(x) != int\n"), "python:S6660").len(),
            1
        );
        // `is`/`is not` identity comparisons stay silent.
        assert!(findings(&scan("exact = type(x) is int\n"), "python:S6660").is_empty());
        assert!(findings(&scan("exact = type(x) is not int\n"), "python:S6660").is_empty());
        assert!(findings(&scan("safe = isinstance(x, int)\n"), "python:S6660").is_empty());
    }

    #[test]
    fn s6660_checks_each_comparison_pair() {
        // Sonar evaluates each operand pair of a comparison chain: an `is`
        // leg never flags, and a `==`/`!=` leg only flags when `type()` is
        // one of its two operands.
        assert!(
            findings(
                &scan("exact = type(x) is int == sentinel\n"),
                "python:S6660"
            )
            .is_empty()
        );
        assert!(findings(&scan("exact = type(x) == 1 == int\n"), "python:S6660").is_empty());
        assert!(findings(&scan("exact = type(x) == type(y)\n"), "python:S6660").is_empty());
        assert_eq!(
            findings(
                &scan("exact = sentinel == type(x) == int\n"),
                "python:S6660"
            )
            .len(),
            1
        );
    }
}
