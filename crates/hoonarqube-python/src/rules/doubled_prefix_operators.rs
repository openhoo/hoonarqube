use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2761 — doubled prefix operators ---------------------------------

pub(crate) fn check_doubled_prefix_operators(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        if let Expr::UnaryOp(unary) = expr
            && let Expr::UnaryOp(inner) = unary.operand.as_ref()
            && unary.op == inner.op
            && matches!(
                unary.op,
                ruff_python_ast::UnaryOp::Not | ruff_python_ast::UnaryOp::Invert
            )
        {
            issues.push(issue_at(
                "python:S2761",
                match unary.op {
                    ruff_python_ast::UnaryOp::Not => {
                        "Use the \"bool()\" builtin function instead of calling \"not\" twice."
                    }
                    ruff_python_ast::UnaryOp::Invert => {
                        "Use the \"~\" operator just once or not at all."
                    }
                    _ => unreachable!("guarded doubled operator"),
                },
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
    fn s2761_flags_doubled_prefix_operators() {
        assert_eq!(
            findings(&scan("b = not not flag\n"), "python:S2761").len(),
            1
        );
        assert_eq!(findings(&scan("c = ~~bits\n"), "python:S2761").len(), 1);
        assert!(findings(&scan("flip = -(-amount)\n"), "python:S2761").is_empty());
    }
}
