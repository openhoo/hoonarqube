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
