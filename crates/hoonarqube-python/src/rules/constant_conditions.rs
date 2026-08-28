use crate::engine::file_context::FileContext;
use crate::support::is_true_literal;
use crate::support::issue_at;
use crate::support::string_value_text;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_constant_conditions(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let test = match stmt {
            Stmt::If(if_stmt) => Some(&if_stmt.test),
            Stmt::While(while_stmt) => Some(&while_stmt.test),
            _ => None,
        };
        if let Some(test) = test
            && constant_truth(test).is_some()
            && !(matches!(stmt, Stmt::While(_)) && is_true_literal(test))
        {
            issues.push(issue_at(
                "python:S5797",
                "Replace this expression; used as a condition it will always be constant.",
                test.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S5797 — constant conditions ---------------------------------------------------

pub(crate) fn constant_truth(expr: &Expr) -> Option<bool> {
    match expr {
        Expr::BooleanLiteral(literal) => Some(literal.value),
        Expr::NoneLiteral(_) => Some(false),
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => value.as_i64().map(|value| value != 0),
            ruff_python_ast::Number::Float(value) => Some(*value != 0.0),
            ruff_python_ast::Number::Complex { .. } => None,
        },
        Expr::StringLiteral(literal) => Some(!string_value_text(&literal.value).is_empty()),
        Expr::BoolOp(bool_op) => {
            let operands: Option<Vec<bool>> = bool_op.values.iter().map(constant_truth).collect();
            operands.map(|operands| match bool_op.op {
                ruff_python_ast::BoolOp::And => operands.iter().all(|value| *value),
                ruff_python_ast::BoolOp::Or => operands.iter().any(|value| *value),
            })
        }
        _ => None,
    }
}
