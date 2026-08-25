// --- literal-kind classification for operator rules

use ruff_python_ast::Expr;

/// Coarse builtin kind of an expression when it is a plain literal; `bool`
/// and `None` are distinct because identity against them is idiomatic.
pub(crate) fn literal_kind(expr: &Expr) -> Option<&'static str> {
    match expr {
        Expr::NumberLiteral(_) => Some("number"),
        Expr::StringLiteral(_) | Expr::FString(_) => Some("string"),
        Expr::BytesLiteral(_) => Some("bytes"),
        Expr::List(_) => Some("list"),
        Expr::Tuple(_) => Some("tuple"),
        Expr::Set(_) => Some("set"),
        Expr::Dict(_) => Some("dict"),
        Expr::BooleanLiteral(_) => Some("boolean"),
        Expr::NoneLiteral(_) => Some("none"),
        _ => None,
    }
}

pub(crate) fn is_identity_op(op: ruff_python_ast::CmpOp) -> bool {
    matches!(
        op,
        ruff_python_ast::CmpOp::Is | ruff_python_ast::CmpOp::IsNot
    )
}

/// `(op, lhs, rhs)` pairs of a comparison expression.
pub(crate) fn comparison_pairs(
    compare: &ruff_python_ast::ExprCompare,
) -> Vec<(ruff_python_ast::CmpOp, &Expr, &Expr)> {
    let mut pairs = Vec::new();
    let mut lhs = compare.left.as_ref();
    for (op, rhs) in compare.ops.iter().zip(compare.comparators.iter()) {
        pairs.push((*op, lhs, rhs));
        lhs = rhs;
    }
    pairs
}
