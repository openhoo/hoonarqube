use crate::engine::file_context::FileContext;
use crate::support::comparison_pairs;
use crate::support::is_identity_op;
use crate::support::issue_at;
use crate::support::literal_kind;
use crate::support::to_u32;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

// --- python:S3403 — identity comparisons of dissimilar types -----------------------

pub(crate) fn check_s3403_identity_dissimilar_types(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        if let Expr::Compare(compare) = expr {
            for (op, lhs, rhs) in comparison_pairs(compare) {
                let mismatch = match (literal_kind(lhs), literal_kind(rhs)) {
                    (Some(left), Some(right)) => left != right,
                    _ => false,
                };
                let none_check =
                    matches!(lhs, Expr::NoneLiteral(_)) || matches!(rhs, Expr::NoneLiteral(_));
                if is_identity_op(op) && mismatch && !none_check {
                    let operator = if op == ruff_python_ast::CmpOp::Is {
                        "is"
                    } else {
                        "is not"
                    };
                    let between = &source[TextRange::new(lhs.end(), rhs.start())];
                    let relative = between.find(operator).expect("identity operator text");
                    let start = lhs.end() + TextSize::from(to_u32(relative));
                    issues.push(issue_at(
                        "python:S3403",
                        &format!(
                            "Remove this \"{operator}\" check; it will always be {}.",
                            if op == ruff_python_ast::CmpOp::Is {
                                "False"
                            } else {
                                "True"
                            }
                        ),
                        TextRange::at(start, TextSize::from(to_u32(operator.len()))),
                        index,
                        source,
                    ));
                }
            }
        }
    }
    issues
}
