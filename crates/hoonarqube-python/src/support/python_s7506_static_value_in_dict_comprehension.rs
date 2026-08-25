// --- python:S7506 — static value in dict comprehension

use crate::support::for_each_expr;
use ruff_python_ast::Expr;

/// Constant expression trees: literals and pure operators only.
pub(crate) fn is_constant_expression(expr: &Expr) -> bool {
    let mut constant = true;
    for_each_expr(expr, &mut |node| {
        constant &= matches!(
            node,
            Expr::NoneLiteral(_)
                | Expr::BooleanLiteral(_)
                | Expr::NumberLiteral(_)
                | Expr::StringLiteral(_)
                | Expr::BytesLiteral(_)
                | Expr::EllipsisLiteral(_)
                | Expr::Tuple(_)
                | Expr::List(_)
                | Expr::Set(_)
                | Expr::UnaryOp(_)
                | Expr::BinOp(_)
                | Expr::BoolOp(_)
                | Expr::Compare(_)
        );
    });
    constant
}
