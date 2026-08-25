use crate::engine::file_context::FileContext;
use crate::support::is_call_to;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S7504 — list() when iterating ---------------------------------------

pub(crate) fn check_list_wrapped_iteration(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::For(for_stmt) = stmt
            && is_call_to(&for_stmt.iter, "list")
        {
            issues.push(issue_at(
                "python:S7504",
                "Iterate over the iterable directly; wrapping it in 'list()' is unnecessary.",
                for_stmt.iter.range(),
                index,
                source,
            ));
        }
    }
    issues
}
