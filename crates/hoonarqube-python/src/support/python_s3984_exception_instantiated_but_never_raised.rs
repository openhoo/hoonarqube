// --- python:S3984 — exception instantiated but never raised

use crate::support::{for_each_expr, for_each_stmt, stmt_exprs};
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;

// ---------------------------------------------------------------------------
// Entries #112–#154 continued: NumPy/Math/Pandas/TensorFlow/scikit-learn/
// PyTorch heuristics and Django conventions.
// ---------------------------------------------------------------------------

/// Visits every expression reachable from a module body, including compound
/// statement headers.
pub(crate) fn for_each_expr_in_module(module_body: &[Stmt], visit: &mut impl FnMut(&Expr)) {
    for_each_stmt(module_body, &mut |stmt| {
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, visit);
        }
    });
}

pub(crate) fn is_zero_number_literal(expr: &Expr) -> bool {
    match expr {
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => value.as_i64() == Some(0),
            ruff_python_ast::Number::Float(value) => *value == 0.0,
            ruff_python_ast::Number::Complex { .. } => false,
        },
        _ => false,
    }
}
