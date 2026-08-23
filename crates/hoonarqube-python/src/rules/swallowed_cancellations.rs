use crate::support::exception_type_names;
use crate::support::for_each_stmt;
use crate::support::issue_at;
use crate::support::suite_contains_raise;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_swallowed_cancellations(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::Try(try_stmt) = stmt else { return };
        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(inner) = handler;
            let caught = exception_type_names(inner.type_.as_deref());
            let cancellation = caught
                .iter()
                .any(|name| matches!(name.as_str(), "CancelledError" | "Cancelled"));
            if cancellation && !suite_contains_raise(&inner.body) {
                issues.push(issue_at(
                    "python:S7497",
                    "Re-raise the cancellation exception after cleanup.",
                    inner.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}
