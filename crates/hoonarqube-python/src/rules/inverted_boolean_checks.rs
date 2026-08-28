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
            && let Expr::Compare(compare) = unary.operand.as_ref()
        {
            let opposite = match compare.ops.first() {
                Some(ruff_python_ast::CmpOp::Eq) => "!=",
                Some(ruff_python_ast::CmpOp::NotEq) => "==",
                Some(ruff_python_ast::CmpOp::Lt) => ">=",
                Some(ruff_python_ast::CmpOp::LtE) => ">",
                Some(ruff_python_ast::CmpOp::Gt) => "<=",
                Some(ruff_python_ast::CmpOp::GtE) => "<",
                Some(ruff_python_ast::CmpOp::Is) => "is not",
                Some(ruff_python_ast::CmpOp::IsNot) => "is",
                Some(ruff_python_ast::CmpOp::In) => "not in",
                Some(ruff_python_ast::CmpOp::NotIn) => "in",
                None => continue,
            };
            issues.push(issue_at(
                "python:S1940",
                &format!("Use the opposite operator (\"{opposite}\") instead."),
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
