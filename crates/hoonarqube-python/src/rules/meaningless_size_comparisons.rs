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
}
