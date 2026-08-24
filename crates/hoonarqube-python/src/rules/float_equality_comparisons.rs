use crate::support::contains_float_literal;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1244 — float equality testing ------------------------------------

pub(crate) fn check_float_equality_comparisons(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Compare(compare) = expr else { return };
        let equality = compare.ops.iter().any(|op| {
            matches!(
                op,
                ruff_python_ast::CmpOp::Eq | ruff_python_ast::CmpOp::NotEq
            )
        });
        if !equality {
            return;
        }
        let float_involved = contains_float_literal(&compare.left)
            || compare.comparators.iter().any(contains_float_literal);
        if float_involved {
            issues.push(issue_at(
                "python:S1244",
                "Compare floating-point values with a tolerance instead of testing equality exactly.",
                compare.range(),
                index,
                source,
            ));
        }
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s1244_flags_exact_float_equality_only() {
        assert_eq!(
            findings(&scan("close = 0.1 + 0.2 == 0.3\n"), "python:S1244").len(),
            1
        );
        for clean in ["cmp = 0.1 < 0.2\n", "ieq = 1 == 2\n"] {
            assert!(findings(&scan(clean), "python:S1244").is_empty(), "{clean}");
        }
    }
}
