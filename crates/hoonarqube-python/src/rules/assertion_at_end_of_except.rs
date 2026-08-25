use crate::support::for_each_stmt;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
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
