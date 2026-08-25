// --- literal-kind helpers for the operator/exception family

use crate::support::literal_kind;
use ruff_python_ast::Expr;

/// Kinds that support neither membership, item access, nor iteration.
const NON_SUPPORTING_KINDS: [&str; 2] = ["number", "boolean"];

pub(crate) fn is_non_supporting_kind(kind: &str) -> bool {
    NON_SUPPORTING_KINDS.contains(&kind)
}

/// Whether `raise <expr>` / `from <expr>` / `except <expr>` is a plain literal
/// that cannot behave like an exception (tuples excluded for legacy forms).
pub(crate) fn is_non_exception_literal(expr: &Expr) -> bool {
    literal_kind(expr).is_some_and(|kind| {
        matches!(
            kind,
            "number" | "string" | "bytes" | "boolean" | "list" | "set" | "dict"
        )
    })
}

pub(crate) fn is_arithmetic_op(op: ruff_python_ast::Operator) -> bool {
    matches!(
        op,
        ruff_python_ast::Operator::Add
            | ruff_python_ast::Operator::Sub
            | ruff_python_ast::Operator::Mult
            | ruff_python_ast::Operator::Div
            | ruff_python_ast::Operator::FloorDiv
            | ruff_python_ast::Operator::Mod
            | ruff_python_ast::Operator::Pow
            | ruff_python_ast::Operator::LShift
            | ruff_python_ast::Operator::RShift
            | ruff_python_ast::Operator::BitAnd
            | ruff_python_ast::Operator::BitOr
            | ruff_python_ast::Operator::BitXor
    )
}

/// Conservative invalidity table for arithmetic between two plain literals.
pub(crate) fn binop_literal_invalid(
    op: ruff_python_ast::Operator,
    left: &str,
    right: &str,
) -> bool {
    let sequence_like = |kind: &str| matches!(kind, "string" | "bytes" | "list" | "tuple");
    if left == "none"
        || right == "none"
        || left == "dict"
        || right == "dict"
        || left == "set"
        || right == "set"
    {
        return true;
    }
    if left == right && matches!(left, "string" | "bytes") {
        return !matches!(op, ruff_python_ast::Operator::Add);
    }
    if left == right && matches!(left, "list" | "tuple") {
        return !matches!(op, ruff_python_ast::Operator::Add);
    }
    let seq_num =
        sequence_like(left) && right == "number" || sequence_like(right) && left == "number";
    if seq_num {
        return !matches!(op, ruff_python_ast::Operator::Mult);
    }
    // Remaining cross-kind pairs (e.g. string with list) are always invalid.
    left != right
}
