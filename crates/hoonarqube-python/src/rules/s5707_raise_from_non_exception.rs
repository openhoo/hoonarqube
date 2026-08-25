use crate::engine::file_context::FileContext;
use crate::support::is_non_exception_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5707 — "__cause__" must be an exception or None -----------------------

pub(crate) fn check_s5707_raise_from_non_exception(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::Raise(raise) = stmt
            && let Some(cause) = raise.cause.as_ref()
            && is_non_exception_literal(cause)
        {
            issues.push(issue_at(
                "python:S5707",
                "Raise from an exception instance or None instead of this value.",
                cause.range(),
                index,
                source,
            ));
        }
    }
    issues
}
