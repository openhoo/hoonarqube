use crate::engine::file_context::FileContext;
use crate::support::for_each_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_constant_dict_comprehension_values(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        if let Expr::DictComp(comp) = expr
            && is_constant_expression(&comp.value)
        {
            issues.push(issue_at(
                "python:S7506",
                "Use 'dict.fromkeys' to build a mapping with a constant value.",
                comp.value.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S7506 — static value in dict comprehension ---------------------------

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
