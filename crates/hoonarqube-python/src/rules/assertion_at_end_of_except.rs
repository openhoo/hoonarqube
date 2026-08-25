use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_assertion_at_end_of_except(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::Try(try_stmt) = stmt else { continue };
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
    }
    issues
}

// --- migrated from support/mod.rs (S5915) ---
// --- python:S5915 — assertion at end of except block ---------------------------

fn is_unittest_assert_call(stmt: &Stmt) -> bool {
    let Stmt::Expr(value) = stmt else {
        return false;
    };
    let Expr::Call(call) = value.value.as_ref() else {
        return false;
    };
    match call.func.as_ref() {
        Expr::Name(name) => name.id.as_str().starts_with("assert"),
        Expr::Attribute(attribute) => attribute.attr.as_str().starts_with("assert"),
        _ => false,
    }
}
