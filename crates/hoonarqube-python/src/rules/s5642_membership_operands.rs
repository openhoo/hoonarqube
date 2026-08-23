use crate::support::comparison_pairs;
use crate::support::for_each_stmt_expr;
use crate::support::is_non_supporting_kind;
use crate::support::issue_at;
use crate::support::literal_kind;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5642 — membership tests on unsupported operands ---------------------

pub(crate) fn check_s5642_membership_operands(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::Compare(compare) = expr {
            for (op, _, rhs) in comparison_pairs(compare) {
                let unsupported = matches!(
                    op,
                    ruff_python_ast::CmpOp::In | ruff_python_ast::CmpOp::NotIn
                ) && literal_kind(rhs).is_some_and(is_non_supporting_kind);
                if unsupported {
                    issues.push(issue_at(
                        "python:S5642",
                        "The right operand of this membership test does not support it.",
                        expr.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    });
    issues
}
