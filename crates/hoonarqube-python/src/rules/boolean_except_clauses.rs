use crate::support::for_each_expr;
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

// --- python:S5714 — boolean expression in except clause -----------------------

pub(crate) fn check_boolean_except_clauses(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::Try(try_stmt) = stmt else { return };
        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(inner) = handler;
            let Some(type_expr) = inner.type_.as_deref() else {
                continue;
            };
            let mut boolean = false;
            for_each_expr(type_expr, &mut |node| {
                boolean |= matches!(node, Expr::BoolOp(_) | Expr::If(_));
            });
            if boolean {
                issues.push(issue_at(
                    "python:S5714",
                    "Simplify this except specification; boolean expressions cannot be caught.",
                    type_expr.range(),
                    index,
                    source,
                ));
            }
        }
    });
    issues
}
