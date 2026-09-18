use crate::support::exprs_textually_equal;
use crate::support::for_each_expr;
use crate::support::for_each_stmt;
use crate::support::for_each_stmt_expr;
use crate::support::issue_at;
use crate::support::ranges_textually_equal;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::ModModule;
use ruff_python_ast::Operator;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

// --- python:S1764 — identical operands ---------------------------------------

/// Binary operators the reference check subscribes to. `+`, `*`, `**`, `@`,
/// and `<<` are never inspected: identical operands there are treated as
/// intentional constant expressions (`60 * 60 * 24 * 7 * 2` style).
fn checked_operator(op: Operator) -> bool {
    matches!(
        op,
        Operator::Sub
            | Operator::Div
            | Operator::FloorDiv
            | Operator::Mod
            | Operator::RShift
            | Operator::BitAnd
            | Operator::BitOr
            | Operator::BitXor
    )
}

/// The reference exempts a pair whose operand is or contains a call: the
/// result is not trivially predictable (e.g. `Q() & Q()`, `f().x - f().x`).
/// Operands are only compared when textually equal, so checking one side is
/// enough.
fn operand_contains_call(expr: &Expr) -> bool {
    let mut contains = false;
    for_each_expr(expr, &mut |node| {
        contains |= matches!(node, Expr::Call(_));
    });
    contains
}

/// The reference exempts any expression inside a `try` statement.
fn try_ranges(stmts: &[Stmt]) -> Vec<TextRange> {
    let mut ranges = Vec::new();
    for_each_stmt(stmts, &mut |stmt| {
        if let Stmt::Try(_) = stmt {
            ranges.push(stmt.range());
        }
    });
    ranges
}

fn in_try(range: TextRange, try_ranges: &[TextRange]) -> bool {
    try_ranges
        .iter()
        .any(|try_range| try_range.contains_range(range))
}

fn identical_operands_issue(range: TextRange, index: &LineIndex, source: &str) -> Issue {
    issue_at(
        "python:S1764",
        "Review this operation; its operands are identical.",
        range,
        index,
        source,
    )
}

pub(crate) fn check_identical_operands(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let try_ranges = try_ranges(parsed.syntax().body.as_slice());
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| match expr {
        Expr::BinOp(binary) => {
            if checked_operator(binary.op)
                && exprs_textually_equal(&binary.left, &binary.right, source)
                && !operand_contains_call(&binary.right)
                && !in_try(binary.range(), &try_ranges)
            {
                issues.push(identical_operands_issue(binary.range(), index, source));
            }
        }
        // The reference folds `and`/`or` chains left-associatively: each step
        // compares the accumulated left operand with the next value.
        Expr::BoolOp(bool_op) => {
            let mut left_end = bool_op.values[0].range().end();
            for value in &bool_op.values[1..] {
                let pair = TextRange::new(bool_op.range().start(), left_end);
                if ranges_textually_equal(pair, value.range(), source)
                    && !operand_contains_call(value)
                    && !in_try(bool_op.range(), &try_ranges)
                {
                    issues.push(identical_operands_issue(
                        TextRange::new(pair.start(), value.range().end()),
                        index,
                        source,
                    ));
                }
                left_end = value.range().end();
            }
        }
        // Chained comparisons fold the same way: `a < b < a` is
        // `(a < b) < a`, which the reference accepts.
        Expr::Compare(compare) => {
            let mut left_end = compare.left.range().end();
            for comparator in &compare.comparators {
                let pair = TextRange::new(compare.range().start(), left_end);
                if ranges_textually_equal(pair, comparator.range(), source)
                    && !operand_contains_call(comparator)
                    && !in_try(compare.range(), &try_ranges)
                {
                    issues.push(identical_operands_issue(
                        TextRange::new(pair.start(), comparator.range().end()),
                        index,
                        source,
                    ));
                }
                left_end = comparator.range().end();
            }
        }
        _ => {}
    });
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s1764_flags_identical_operands_on_checked_operators() {
        // Sonar checks -, /, //, %, >>, &, |, ^, and, or, comparisons, is, in.
        for flagged in [
            "z = x - x\n",
            "z = x / x\n",
            "z = x // x\n",
            "z = x % x\n",
            "z = x >> x\n",
            "z = x & x\n",
            "z = x | x\n",
            "z = x ^ x\n",
            "z = x and x\n",
            "z = x or x\n",
            "q = x == x\n",
            "q = x != x\n",
            "q = x < x\n",
            "q = x is x\n",
            "q = x in x\n",
            "j = 5 / 5\n",
            "k = 5 - 5\n",
        ] {
            assert_eq!(
                findings(&scan(flagged), "python:S1764").len(),
                1,
                "{flagged}"
            );
        }
    }

    #[test]
    fn s1764_skips_operators_sonar_never_checks() {
        // Sonar never subscribes to +, *, **, @, or << — identical operands on
        // those operators are intentional constant expressions like
        // `60 * 60 * 24 * 7 * 2` (django/conf/global_settings.py:493).
        for clean in [
            "z = x + x\n",
            "z = x * x\n",
            "z = x ** x\n",
            "z = x @ x\n",
            "z = x << x\n",
            "v = 60 * 60 * 24 * 7 * 2\n",
            "w = 10**10 - 1\n",
            "z = x * 2\n",
        ] {
            assert!(findings(&scan(clean), "python:S1764").is_empty(), "{clean}");
        }
    }

    #[test]
    fn s1764_exempts_call_operands_and_try_bodies() {
        // Sonar exempts a pair whose operand is or contains a call, and any
        // expression inside a try statement (django Q() & Q(), F() + F()).
        for clean in [
            "z = f() - f()\n",
            "z = f().x - f().x\n",
            "z = Q() & Q()\n",
            "z = F(\"pink\") + F(\"pink\")\n",
            "try:\n    z = x - x\nexcept ValueError:\n    pass\n",
            "try:\n    pass\nexcept ValueError:\n    z = x - x\n",
            "try:\n    pass\nfinally:\n    z = x - x\n",
        ] {
            assert!(findings(&scan(clean), "python:S1764").is_empty(), "{clean}");
        }
        // Outside a try the same expression is still flagged.
        assert_eq!(findings(&scan("z = x - x\n"), "python:S1764").len(), 1);
    }

    #[test]
    fn s1764_models_left_associative_chains() {
        // Sonar folds and/or/comparison chains left-associatively: the
        // accumulated left operand is compared with each right operand.
        assert_eq!(
            findings(&scan("z = a or a or b\n"), "python:S1764").len(),
            1
        );
        assert_eq!(
            findings(&scan("z = a or b or a\n"), "python:S1764").len(),
            0
        );
        assert_eq!(findings(&scan("z = a and a\n"), "python:S1764").len(), 1);
        // `a == b or a == b` flags the or-node (RSPEC noncompliant example).
        assert_eq!(
            findings(&scan("if a == b or a == b:\n    pass\n"), "python:S1764").len(),
            1
        );
        // Chained comparisons compare the accumulated left, not the first
        // operand: `a < b < a` is `(a < b) < a`, which Sonar accepts.
        assert_eq!(findings(&scan("q = a < b < a\n"), "python:S1764").len(), 0);
        assert_eq!(findings(&scan("q = a < a < b\n"), "python:S1764").len(), 1);
    }
}
