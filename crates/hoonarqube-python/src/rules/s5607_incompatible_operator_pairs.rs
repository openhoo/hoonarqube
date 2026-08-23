use crate::support::binop_literal_invalid;
use crate::support::for_each_stmt_expr;
use crate::support::is_arithmetic_op;
use crate::support::issue_at;
use crate::support::literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5607 — operators between incompatible literal types -------------------

pub(crate) fn check_s5607_incompatible_operator_pairs(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::BinOp(binop) = expr {
            if !is_arithmetic_op(binop.op) {
                return;
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
    });
    issues
}
