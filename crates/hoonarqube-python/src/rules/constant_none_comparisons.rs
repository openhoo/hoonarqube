use crate::engine::file_context::FileContext;
use crate::support::constant_literal_text;
use crate::support::is_none_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5727 — constant comparison to None -------------------------------

pub(crate) fn check_constant_none_comparisons(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Compare(compare) = expr else {
            continue;
        };
        let mut sides: Vec<&Expr> = vec![&compare.left];
        sides.extend(&compare.comparators);
        let constant_involved = sides.iter().any(|side| {
            is_none_literal(side)
                && sides.iter().any(|other| {
                    !std::ptr::eq(*side, *other) && constant_literal_text(other).is_some()
                })
        });
        if constant_involved {
            let (operator, outcome) = match compare.ops.first() {
                Some(ruff_python_ast::CmpOp::Eq | ruff_python_ast::CmpOp::Is) => (
                    if compare.ops[0] == ruff_python_ast::CmpOp::Eq {
                        "=="
                    } else {
                        "is"
                    },
                    "False",
                ),
                Some(ruff_python_ast::CmpOp::NotEq | ruff_python_ast::CmpOp::IsNot) => (
                    if compare.ops[0] == ruff_python_ast::CmpOp::NotEq {
                        "!="
                    } else {
                        "is not"
                    },
                    "True",
                ),
                _ => continue,
            };
            issues.push(issue_at(
                "python:S5727",
                &format!("Remove this {operator} comparison; it will always be {outcome}."),
                compare.range(),
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
    fn s5727_flags_constant_none_comparisons() {
        assert_eq!(
            findings(&scan("same = None == None\n"), "python:S5727").len(),
            1
        );
        assert_eq!(
            findings(&scan("odd = \"x\" == None\n"), "python:S5727").len(),
            1
        );
        assert!(findings(&scan("maybe = x == None\n"), "python:S5727").is_empty());
    }
}
