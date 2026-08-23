use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use crate::support::len_zero_verdict;
use crate::support::len_zero_verdict_swapped;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S3981 — meaningless collection-size comparisons ------------------

pub(crate) fn check_meaningless_size_comparisons(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Compare(compare) = expr else { return };
        let meaningless = compare
            .ops
            .iter()
            .zip(&compare.comparators)
            .any(|(op, comparator)| {
                len_zero_verdict(&compare.left, comparator, *op)
                    || len_zero_verdict_swapped(&compare.left, comparator, *op)
            });
        if meaningless {
            issues.push(issue_at(
                "python:S3981",
                "Review this meaningless collection-size comparison.",
                compare.range(),
                index,
                source,
            ));
        }
    });
    issues
}
