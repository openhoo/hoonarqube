use crate::support::for_each_stmt;
use crate::support::is_non_exception_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5708 — caught values derive from BaseException ------------------------

pub(crate) fn check_s5708_excepting_non_exceptions(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
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
    });
    issues
}
