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
                if let Some(issue) = dissimilar_identity_issue(op, lhs, rhs, index, source) {
                    issues.push(issue);
                }
            }
        }
    }
    issues
}

fn dissimilar_identity_issue(
    op: ruff_python_ast::CmpOp,
    lhs: &Expr,
    rhs: &Expr,
    index: &LineIndex,
    source: &str,
) -> Option<Issue> {
    let mismatch = literal_kind(lhs)
        .zip(literal_kind(rhs))
        .is_some_and(|(left, right)| left != right);
    let compares_none = matches!(lhs, Expr::NoneLiteral(_)) || matches!(rhs, Expr::NoneLiteral(_));
    if !is_identity_op(op) || !mismatch || compares_none {
        return None;
    }
    let (operator, result) = if op == ruff_python_ast::CmpOp::Is {
        ("is", "False")
    } else {
        ("is not", "True")
    };
    let between = &source[TextRange::new(lhs.end(), rhs.start())];
    let relative = between.find(operator)?;
    let start = lhs.end() + TextSize::from(to_u32(relative));
    Some(issue_at(
        "python:S3403",
        &format!("Remove this \"{operator}\" check; it will always be {result}."),
        TextRange::at(start, TextSize::from(to_u32(operator.len()))),
        index,
        source,
    ))
}
