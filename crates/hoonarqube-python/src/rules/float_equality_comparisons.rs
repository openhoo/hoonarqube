use crate::engine::file_context::FileContext;
use crate::support::contains_float_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1244 — float equality testing ------------------------------------

pub(crate) fn check_float_equality_comparisons(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Compare(compare) = expr else {
            continue;
        };
        let left_operands = std::iter::once(compare.left.as_ref()).chain(&compare.comparators);
        let float_equality = left_operands
            .zip(&compare.ops)
            .zip(&compare.comparators)
            .any(|((left, op), right)| {
                matches!(
                    op,
                    ruff_python_ast::CmpOp::Eq | ruff_python_ast::CmpOp::NotEq
                ) && (is_float_operand(left) || is_float_operand(right))
            });
        if float_equality {
            issues.push(issue_at(
                "python:S1244",
                "Compare floating-point values with a tolerance instead of testing equality exactly.",
                compare.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// Follow numeric expressions, not arbitrary descendants: a float inside a
// collection or a call argument does not make the operand itself a float.
fn is_float_operand(expr: &Expr) -> bool {
    match expr {
        Expr::NumberLiteral(_) => contains_float_literal(expr),
        Expr::UnaryOp(unary)
            if matches!(
                unary.op,
                ruff_python_ast::UnaryOp::UAdd | ruff_python_ast::UnaryOp::USub
            ) =>
        {
            is_float_operand(&unary.operand)
        }
        Expr::BinOp(binary)
            if matches!(
                binary.op,
                ruff_python_ast::Operator::Add
                    | ruff_python_ast::Operator::Sub
                    | ruff_python_ast::Operator::Mult
                    | ruff_python_ast::Operator::Div
                    | ruff_python_ast::Operator::FloorDiv
                    | ruff_python_ast::Operator::Mod
                    | ruff_python_ast::Operator::Pow
            ) =>
        {
            is_float_operand(&binary.left) || is_float_operand(&binary.right)
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, pos, scan};

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

    #[test]
    fn s1244_distinguishes_extent_tuple_from_direct_tolerance() {
        let source = "class F:\n    def deconstruct(self):\n        if self._extent != (-180.0, -90.0, 180.0, 90.0):\n            pass\n        if self._tolerance != 0.05:\n            pass\n";
        let report = scan(source);
        let issues = findings(&report, "python:S1244");
        let ranges: Vec<_> = issues.iter().map(|issue| issue.range.clone()).collect();
        assert_eq!(
            ranges,
            vec![hoonarqube_ir::Range {
                start: pos(5, 12),
                end: pos(5, 35),
            }]
        );
    }

    #[test]
    fn s1244_does_not_infer_float_type_from_nested_values() {
        for source in [
            "(-180.0, -90.0) == extent\n",
            "extent == ((-180.0,), (90.0,))\n",
            "values == [0.1, 0.2]\n",
            "value == convert(0.1)\n",
            "value == (not 0.1)\n",
            "0.1 < lower == upper\n",
            "lower == upper < 0.1\n",
        ] {
            assert!(findings(&scan(source), "python:S1244").is_empty(), "{source}");
        }
    }

    #[test]
    fn s1244_preserves_numeric_operands_and_adjacent_chain_equalities() {
        for (source, end_column) in [
            ("value == (-0.5)\n", 16),
            ("(+0.5) != value\n", 16),
            ("0.1 + 0.2 == value\n", 19),
            ("lower < 0.1 == upper\n", 21),
            ("lower == 0.1 < upper\n", 21),
            ("0.1 == middle != 0.2\n", 21),
        ] {
            let report = scan(source);
            let issues = findings(&report, "python:S1244");
            let ranges: Vec<_> = issues.iter().map(|issue| issue.range.clone()).collect();
            assert_eq!(
                ranges,
                vec![hoonarqube_ir::Range {
                    start: pos(1, 1),
                    end: pos(1, end_column),
                }],
                "{source}"
            );
        }
    }
}
