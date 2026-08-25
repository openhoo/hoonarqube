use crate::engine::file_context::FileContext;
use crate::support::comparison_pairs;
use crate::support::is_identity_op;
use crate::support::issue_at;
use crate::support::literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

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
                if is_identity_op(op) && mismatch {
                    issues.push(issue_at(
                        "python:S3403",
                        "These literals have different types and can never be identical.",
                        expr.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    }
    issues
}
