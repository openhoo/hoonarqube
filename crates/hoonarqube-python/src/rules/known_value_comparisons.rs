use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::CmpOp;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2159 — self-comparison equality checks ----------------------------
//
// CE/RSPEC scope: an equality comparison whose two operands are the same name
// always evaluates identically. Constant-folding through known initializers is
// an extension beyond the CE engine and deliberately stays out of scope.

pub(crate) fn check_known_value_comparisons(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Compare(compare) = expr else {
            continue;
        };
        let operands: Vec<&Expr> = std::iter::once(&*compare.left)
            .chain(compare.comparators.iter())
            .collect();
        for position in 0..compare.ops.len() {
            if !matches!(compare.ops[position], CmpOp::Eq | CmpOp::NotEq) {
                continue;
            }
            let (Expr::Name(left), Expr::Name(right)) =
                (operands[position], operands[position + 1])
            else {
                continue;
            };
            if left.id == right.id {
                issues.push(issue_at(
                    "python:S2159",
                    &format!(
                        "This comparison always evaluates the same way; '{}' appears on both sides.",
                        left.id.as_str()
                    ),
                    compare.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}
