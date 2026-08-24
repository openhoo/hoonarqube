use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2761 — doubled prefix operators ---------------------------------

pub(crate) fn check_doubled_prefix_operators(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
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
                "Remove this doubled prefix operator.",
                unary.range(),
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
    fn s2761_flags_doubled_prefix_operators() {
        assert_eq!(
            findings(&scan("b = not not flag\n"), "python:S2761").len(),
            1
        );
        assert_eq!(findings(&scan("c = ~~bits\n"), "python:S2761").len(), 1);
        assert!(findings(&scan("flip = -(-amount)\n"), "python:S2761").is_empty());
    }
}
