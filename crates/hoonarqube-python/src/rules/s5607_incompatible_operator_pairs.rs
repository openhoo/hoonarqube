use crate::engine::file_context::FileContext;
use crate::support::binop_literal_invalid;
use crate::support::is_arithmetic_op;
use crate::support::issue_at;
use crate::support::literal_kind;
use crate::support::to_u32;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

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
                let between = &source[TextRange::new(binop.left.end(), binop.right.start())];
                let operator = between.trim();
                let leading = between.len() - between.trim_start().len();
                let operator_start = binop.left.end() + TextSize::from(to_u32(leading));
                issues.push(issue_at(
                    "python:S5607",
                    &format!(
                        "Fix this invalid \"{operator}\" operation between incompatible types ({} and {}).",
                        python_type_name(binop.left.as_ref()),
                        python_type_name(binop.right.as_ref())
                    ),
                    TextRange::new(
                        operator_start,
                        operator_start + TextSize::from(to_u32(operator.len())),
                    ),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

fn python_type_name(expr: &Expr) -> &'static str {
    match expr {
        Expr::NumberLiteral(number) => match number.value {
            ruff_python_ast::Number::Int(_) => "int",
            ruff_python_ast::Number::Float(_) => "float",
            ruff_python_ast::Number::Complex { .. } => "complex",
        },
        Expr::StringLiteral(_) | Expr::FString(_) => "str",
        Expr::BytesLiteral(_) => "bytes",
        Expr::List(_) => "list",
        Expr::Tuple(_) => "tuple",
        Expr::Set(_) => "set",
        Expr::Dict(_) => "dict",
        Expr::BooleanLiteral(_) => "bool",
        Expr::NoneLiteral(_) => "NoneType",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s5607_flags_incompatible_literal_arithmetic_only() {
        let bad = scan("result = 'value' - 1\n");
        assert_eq!(findings(&bad, "python:S5607").len(), 1);

        let good = scan("result = 'value' * 2\n");
        assert!(findings(&good, "python:S5607").is_empty());
    }
}
