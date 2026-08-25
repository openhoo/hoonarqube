use crate::engine::file_context::FileContext;
use crate::support::is_non_exception_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5708 — caught values derive from BaseException ------------------------

pub(crate) fn check_s5708_excepting_non_exceptions(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::Try(try_) = stmt {
            for handler in &try_.handlers {
                let ExceptHandler::ExceptHandler(inner) = handler;
                if let Some(handled) = inner.type_.as_ref()
                    && is_non_exception_literal(handled)
                {
                    issues.push(issue_at(
                        "python:S5708",
                        "Catch an exception derived from BaseException.",
                        handled.range(),
                        index,
                        source,
                    ));
                }
            }
        }
    }
    issues
}
