use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1940 — inverted boolean checks ----------------------------------

pub(crate) fn check_inverted_boolean_checks(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        if let Expr::UnaryOp(unary) = expr
            && unary.op == ruff_python_ast::UnaryOp::Not
            && matches!(unary.operand.as_ref(), Expr::Compare(_))
        {
            issues.push(issue_at(
                "python:S1940",
                "Replace this negated comparison with the inverted operator.",
                unary.range(),
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
    fn s1940_flags_negated_comparisons() {
        assert_eq!(
            findings(&scan("ok = not (a == b)\n"), "python:S1940").len(),
            1
        );
        assert!(findings(&scan("fine = not (a and b)\n"), "python:S1940").is_empty());
    }
}
