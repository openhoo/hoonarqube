use crate::support::excluded_identical_pair;
use crate::support::exprs_textually_equal;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1764 — identical operands ---------------------------------------

pub(crate) fn check_identical_operands(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| match expr {
        Expr::BinOp(binary) => {
            if exprs_textually_equal(&binary.left, &binary.right, source)
                && !excluded_identical_pair(&binary.left, &binary.right)
            {
                issues.push(issue_at(
                    "python:S1764",
                    "Review this operation; its operands are identical.",
                    binary.range(),
                    index,
                    source,
                ));
            }
        }
        Expr::Compare(compare) => {
            for comparator in &compare.comparators {
                if exprs_textually_equal(&compare.left, comparator, source)
                    && !excluded_identical_pair(&compare.left, comparator)
                {
                    issues.push(issue_at(
                        "python:S1764",
                        "Review this operation; its operands are identical.",
                        compare.range(),
                        index,
                        source,
                    ));
                    break;
                }
            }
        }
        _ => {}
    });
    issues
}
