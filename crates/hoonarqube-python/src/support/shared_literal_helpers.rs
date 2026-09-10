// --- shared literal helpers

use ruff_python_ast::Expr;

/// Whether `expr` is a plain string or bytes literal (static by construction).
pub(crate) fn is_static_text_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::StringLiteral(_) | Expr::BytesLiteral(_))
}
