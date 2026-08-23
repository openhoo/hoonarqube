use crate::support::for_each_stmt_expr;
use crate::support::is_type_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S6660 — `type()` equality instead of isinstance -------------------

pub(crate) fn check_type_equality_comparisons(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Compare(compare) = expr else { return };
        if !compare.ops.iter().any(|op| {
            matches!(
                op,
                ruff_python_ast::CmpOp::Eq
                    | ruff_python_ast::CmpOp::NotEq
                    | ruff_python_ast::CmpOp::Is
                    | ruff_python_ast::CmpOp::IsNot
            )
        }) {
            return;
        }
        let mut sides: Vec<&Expr> = vec![&compare.left];
        sides.extend(&compare.comparators);
        let flagged = sides.iter().any(|side| {
            is_type_call(side)
                && sides.iter().any(|other| {
                    !std::ptr::eq(*side, *other)
                        && matches!(other, Expr::Name(_) | Expr::Attribute(_))
                })
        });
        if flagged {
            issues.push(issue_at(
                "python:S6660",
                "Use 'isinstance' instead of comparing the result of 'type()' directly.",
                compare.range(),
                index,
                source,
            ));
        }
    });
    issues
}
