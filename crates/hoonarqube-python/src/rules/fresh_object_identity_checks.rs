use crate::engine::file_context::FileContext;
use crate::support::is_freshly_created;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5796 — identity check on freshly created objects ----------------

pub(crate) fn check_fresh_object_identity_checks(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Compare(compare) = expr else {
            continue;
        };
        let identity = compare.ops.iter().any(|op| {
            matches!(
                op,
                ruff_python_ast::CmpOp::Is | ruff_python_ast::CmpOp::IsNot
            )
        });
        if !identity {
            continue;
        }
        let mut sides: Vec<&Expr> = vec![&compare.left];
        sides.extend(&compare.comparators);
        if sides.iter().any(|side| is_freshly_created(side)) {
            let Some((position, operator)) = compare.ops.iter().enumerate().find(|(_, op)| {
                matches!(
                    op,
                    ruff_python_ast::CmpOp::Is | ruff_python_ast::CmpOp::IsNot
                )
            }) else {
                continue;
            };
            let left_end = if position == 0 {
                compare.left.end()
            } else {
                compare.comparators[position - 1].end()
            };
            let right_start = compare.comparators[position].start();
            let between = &source[ruff_text_size::TextRange::new(left_end, right_start)];
            let operator_text = if *operator == ruff_python_ast::CmpOp::Is {
                "is"
            } else {
                "is not"
            };
            let Some(relative) = between.find(operator_text) else {
                continue;
            };
            let operator_start =
                left_end + ruff_text_size::TextSize::from(crate::support::to_u32(relative));
            issues.push(issue_at(
                "python:S5796",
                &format!("Replace this \"{operator_text}\" operator with \"==\"."),
                ruff_text_size::TextRange::new(
                    operator_start,
                    operator_start
                        + ruff_text_size::TextSize::from(crate::support::to_u32(
                            operator_text.len(),
                        )),
                ),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5796_flags_identity_on_fresh_objects() {
        assert_eq!(
            findings(&scan("never = [] is []\n"), "python:S5796").len(),
            1
        );
        assert_eq!(
            findings(&scan("fresh = list() is other\n"), "python:S5796").len(),
            1
        );
        assert!(findings(&scan("ref = a is b\n"), "python:S5796").is_empty());
    }
}
