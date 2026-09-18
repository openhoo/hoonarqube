use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCompare};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S1940 — inverted boolean checks ----------------------------------

pub(crate) fn check_inverted_boolean_checks(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        if let Expr::UnaryOp(unary) = expr
            && unary.op == ruff_python_ast::UnaryOp::Not
            && let Expr::Compare(compare) = unary.operand.as_ref()
            // Sonar's checkNotExpression returns early only when the
            // outer comparison's left operand is itself a comparison —
            // `not (0 <= index < size)` stays silent, while chains that
            // continue through `in`/`is` are still flagged.
            && !is_sonar_silent_chain(compare)
        {
            let opposite = match compare.ops.last() {
                Some(ruff_python_ast::CmpOp::Eq) => "!=",
                Some(ruff_python_ast::CmpOp::NotEq) => "==",
                Some(ruff_python_ast::CmpOp::Lt) => ">=",
                Some(ruff_python_ast::CmpOp::LtE) => ">",
                Some(ruff_python_ast::CmpOp::Gt) => "<=",
                Some(ruff_python_ast::CmpOp::GtE) => "<",
                Some(ruff_python_ast::CmpOp::Is) => "is not",
                Some(ruff_python_ast::CmpOp::IsNot) => "is",
                Some(ruff_python_ast::CmpOp::In) => "not in",
                Some(ruff_python_ast::CmpOp::NotIn) => "in",
                None => continue,
            };
            issues.push(issue_at(
                "python:S1940",
                &format!("Use the opposite operator (\"{opposite}\") instead."),
                unary.range(),
                index,
                source,
            ));
        }
    }
    issues
}

/// `SonarPython` parses `a < b < c` as a left-associative binary chain, so
/// `checkNotExpression` stays silent only when the outer operator is a
/// plain comparison whose left operand is another plain comparison. In
/// ruff's flattened `Compare` that is exactly a chain whose last two
/// operators are both plain comparisons; a chain whose outer or
/// penultimate operator is `in`/`is`/`not in`/`is not` is still flagged.
fn is_sonar_silent_chain(compare: &ExprCompare) -> bool {
    compare.ops.len() >= 2
        && compare.ops.iter().rev().take(2).all(|op| {
            matches!(
                op,
                ruff_python_ast::CmpOp::Eq
                    | ruff_python_ast::CmpOp::NotEq
                    | ruff_python_ast::CmpOp::Lt
                    | ruff_python_ast::CmpOp::LtE
                    | ruff_python_ast::CmpOp::Gt
                    | ruff_python_ast::CmpOp::GtE
            )
        })
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s1940_flags_negated_comparisons() {
        assert_eq!(
            findings(&scan("ok = not (a == b)\n"), "python:S1940").len(),
            1
        );
        assert!(findings(&scan("fine = not (a and b)\n"), "python:S1940").is_empty());
    }

    #[test]
    fn s1940_skips_negated_plain_comparison_chains() {
        for source in [
            "ok = not (0 <= index < size)\n",
            "ok = not 1 <= len(params) <= 3\n",
            "ok = not (a < b < c < d)\n",
            "ok = not ((a < b) < c < d)\n",
        ] {
            assert!(
                findings(&scan(source), "python:S1940").is_empty(),
                "Sonar stays silent on {source:?}"
            );
        }
    }

    #[test]
    fn s1940_flags_negated_chains_through_in_and_is() {
        // SonarPython parses `in`/`is` as distinct tree kinds, so a chain
        // whose outer or penultimate operator is `in`/`is` is still
        // flagged; only plain-comparison chains stay silent.
        let flagged = [
            ("ok = not (a in b in c)\n", "not in"),
            ("ok = not (a is b is c)\n", "is not"),
            ("ok = not (a in b < c)\n", ">="),
            ("ok = not (a < b in c)\n", "not in"),
            ("ok = not (a < b is c)\n", "is not"),
            ("ok = not ((a < b) < c)\n", ">="),
        ];
        for (source, opposite) in flagged {
            let report = scan(source);
            let matches = findings(&report, "python:S1940");
            assert_eq!(matches.len(), 1, "expected one finding for {source:?}");
            assert_eq!(
                matches[0].message,
                format!("Use the opposite operator (\"{opposite}\") instead."),
                "outermost operator decides the suggestion for {source:?}"
            );
        }
    }
}
