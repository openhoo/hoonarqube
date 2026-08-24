use crate::support::dotted_name;
use crate::support::for_each_expr_in_module;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_nan_comparisons(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_expr_in_module(parsed.syntax().body.as_slice(), &mut |expr| {
        if let Expr::Compare(compare) = expr {
            let touches_nan =
                is_numpy_nan(&compare.left) || compare.comparators.iter().any(is_numpy_nan);
            let equality_shaped = compare.ops.iter().any(|op| {
                matches!(
                    op,
                    ruff_python_ast::CmpOp::Eq
                        | ruff_python_ast::CmpOp::NotEq
                        | ruff_python_ast::CmpOp::Is
                        | ruff_python_ast::CmpOp::IsNot
                )
            });
            if touches_nan && equality_shaped {
                issues.push(issue_at(
                    "python:S6725",
                    "Test for NaN with math.isnan or np.isnan instead of comparing.",
                    compare.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}

// --- migrated from support/mod.rs (S6725) ---
// --- python:S6725 — equality against numpy.nan --------------------------------

pub(crate) fn is_numpy_nan(expr: &Expr) -> bool {
    dotted_name(expr).is_some_and(|path| matches!(path.as_str(), "np.nan" | "numpy.nan"))
}
