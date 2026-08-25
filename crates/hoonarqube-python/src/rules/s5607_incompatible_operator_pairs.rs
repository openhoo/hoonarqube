use crate::engine::file_context::FileContext;
use crate::support::binop_literal_invalid;
use crate::support::is_arithmetic_op;
use crate::support::issue_at;
use crate::support::literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5607 — operators between incompatible literal types -------------------

pub(crate) fn check_s5607_incompatible_operator_pairs(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        if let Expr::BinOp(binop) = expr {
            if !is_arithmetic_op(binop.op) {
                continue;
            }
            if let (Some(left), Some(right)) = (
                literal_kind(binop.left.as_ref()),
                literal_kind(binop.right.as_ref()),
            ) && binop_literal_invalid(binop.op, left, right)
            {
                issues.push(issue_at(
                    "python:S5607",
                    "These operand types do not support this operator.",
                    expr.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}
