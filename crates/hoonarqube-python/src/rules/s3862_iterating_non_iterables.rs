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
        let bad_iter = match stmt {
            Stmt::For(loop_) => Some(loop_.iter.as_ref()),
            _ => None,
        };
        let bad_yield = stmt_exprs(stmt).into_iter().any(|expr| {
            matches!(expr, Expr::YieldFrom(yield_from)
                if literal_kind(yield_from.value.as_ref()).is_some_and(is_non_supporting_kind))
        });
        let non_iterable = bad_yield
            || bad_iter.is_some_and(|iter| {
                literal_kind(iter).is_some_and(is_non_supporting_kind)
                    || matches!(iter, Expr::Call(call) if called_name(&call.func).is_some_and(|name| matches!(name, "len" | "int")))
            });
        if non_iterable {
            issues.push(issue_at(
                "python:S3862",
                "Iterate over an object that supports iteration.",
                stmt.range(),
                index,
                source,
            ));
        }
    }
    issues
}
