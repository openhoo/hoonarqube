use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use crate::support::len_zero_verdict;
use crate::support::len_zero_verdict_swapped;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S3981 — meaningless collection-size comparisons ------------------

pub(crate) fn check_meaningless_size_comparisons(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for expr in &file_ctx.exprs {
        let Expr::Compare(compare) = expr else {
            continue;
        };
        // Chained comparisons pair each comparator with the previous
        // operand — `0 < value <= len(choices)` tests `value <= len(...)`,
        // not `0 <= len(...)`.
        let meaningless = compare
            .ops
            .iter()
            .zip(&compare.comparators)
            .enumerate()
            .any(|(index, (op, comparator))| {
                let left = if index == 0 {
                    &compare.left
                } else {
                    &compare.comparators[index - 1]
                };
                len_zero_verdict(left, comparator, *op)
                    || len_zero_verdict_swapped(left, comparator, *op)
            });
        if meaningless {
            issues.push(issue_at(
                "python:S3981",
                "The length of a collection is always \">=0\", so update this test to either \"==0\" or \">0\".",
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
    fn s3981_len_zero_comparison_table() {
        for source in [
            "if len(xs) >= 0:\n    show()\n",
            "if 0 <= len(xs):\n    show()\n",
            "if len(xs) <= 0:\n    show()\n",
            "if len(xs) < 0:\n    show()\n",
            "if 0 > len(xs):\n    show()\n",
            "if 0 >= len(xs):\n    show()\n",
        ] {
            assert_eq!(findings(&scan(source), "python:S3981").len(), 1, "{source}");
        }
        for clean in [
            "if len(xs) == 0:\n    show()\n",
            "if len(xs) < 5:\n    show()\n",
        ] {
            assert!(findings(&scan(clean), "python:S3981").is_empty(), "{clean}");
        }
    }

    #[test]
    fn s3981_chained_zero_comparison_still_flags() {
        let chained = scan("if 0 <= len(xs) < 10:\n    show()\n");
        assert_eq!(findings(&chained, "python:S3981").len(), 1);
    }

    #[test]
    fn s3981_chained_comparison_pairs_adjacent_operands() {
        // Issue #636: in `0 < value <= len(choices)` the second pair is
        // `value <= len(choices)`, not `0 <= len(choices)` — Sonar emits
        // nothing because no adjacent pair compares a length against zero.
        for clean in [
            "def f(choices, value):\n    if 0 < value <= len(choices):\n        return value\n",
            "def f(source, start, end):\n    if 0 <= start <= end <= len(source):\n        return source[start:end]\n",
            "if a < b < c:\n    show()\n",
            "if len(a) == len(b):\n    show()\n",
        ] {
            assert!(findings(&scan(clean), "python:S3981").is_empty(), "{clean}");
        }
        // A meaningless len-vs-zero pair inside a chain is still flagged.
        for flagged in [
            "if 0 <= len(xs) < 10:\n    show()\n",
            "if 5 > len(xs) >= 0:\n    show()\n",
            "if len(xs) >= 0 and check():\n    show()\n",
        ] {
            assert_eq!(
                findings(&scan(flagged), "python:S3981").len(),
                1,
                "{flagged}"
            );
        }
    }
}
