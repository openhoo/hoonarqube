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

pub(crate) fn check_s5795_identity_cached_types(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        if let Expr::Compare(compare) = expr {
            for (op, lhs, rhs) in comparison_pairs(compare) {
                let unsafe_side = |e: &Expr| {
                    literal_kind(e).is_some_and(|kind| IDENTITY_UNSAFE_KINDS.contains(&kind))
                };
                if is_identity_op(op) && (unsafe_side(lhs) || unsafe_side(rhs)) {
                    let operator = if op == ruff_python_ast::CmpOp::Is {
                        "is"
                    } else {
                        "is not"
                    };
                    let between = &source[TextRange::new(lhs.end(), rhs.start())];
                    let Some(relative) = between.find(operator) else {
                        continue;
                    };
                    let operator_start = lhs.end() + TextSize::from(to_u32(relative));
                    issues.push(issue_at(
                        "python:S5795",
                        &format!(
                            "Replace this \"{operator}\" operator with \"{}\"; identity operator is not reliable here.",
                            if op == ruff_python_ast::CmpOp::Is { "==" } else { "!=" }
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
    }
    issues
}

// --- python:S5795 — identity comparisons with cached types -------------------------

const IDENTITY_UNSAFE_KINDS: [&str; 3] = ["number", "string", "bytes"];
