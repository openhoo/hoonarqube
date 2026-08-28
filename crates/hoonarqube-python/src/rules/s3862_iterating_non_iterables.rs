use crate::engine::file_context::FileContext;
use crate::support::called_name;
use crate::support::is_non_supporting_kind;
use crate::support::issue_at;
use crate::support::literal_kind;
use crate::support::stmt_exprs;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S3862 — iterating non-iterables ---------------------------------------

pub(crate) fn check_s3862_iterating_non_iterables(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::For(loop_) = stmt {
            let iter = loop_.iter.as_ref();
            if literal_kind(iter).is_some_and(is_non_supporting_kind)
                || matches!(iter, Expr::Call(call) if called_name(&call.func).is_some_and(|name| matches!(name, "len" | "int")))
            {
                issues.push(issue_at(
                    "python:S3862",
                    "Replace this expression with an iterable object.",
                    iter.range(),
                    index,
                    source,
                ));
            }
        }
        for expr in stmt_exprs(stmt) {
            if let Expr::YieldFrom(yield_from) = expr
                && literal_kind(yield_from.value.as_ref()).is_some_and(is_non_supporting_kind)
            {
                issues.push(issue_at(
                    "python:S3862",
                    "Replace this expression with an iterable object.",
                    yield_from.value.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s3862_flags_literal_and_known_non_iterable_loop_sources() {
        let bad =
            scan("for item in 42:\n    consume(item)\nfor item in int('2'):\n    consume(item)\n");
        assert_eq!(findings(&bad, "python:S3862").len(), 2);

        let good = scan("for item in [1, 2]:\n    consume(item)\n");
        assert!(findings(&good, "python:S3862").is_empty());
    }
}
