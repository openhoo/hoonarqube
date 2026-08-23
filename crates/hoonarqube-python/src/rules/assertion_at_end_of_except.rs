use crate::support::for_each_stmt;
use crate::support::is_unittest_assert_call;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::ModModule;
use ruff_python_ast::Stmt;
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_assertion_at_end_of_except(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::Try(try_stmt) = stmt else { return };
        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(inner) = handler;
            if let Some(last) = inner.body.last()
                && is_unittest_assert_call(last)
            {
                issues.push(issue_at(
                    "python:S5915",
                    "Asserting at the end of an 'except' block masks the original exception.",
                    last.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}
