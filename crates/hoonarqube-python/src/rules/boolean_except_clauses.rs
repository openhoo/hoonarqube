use crate::engine::file_context::FileContext;
use crate::support::for_each_expr;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S5714 — boolean expression in except clause -----------------------

pub(crate) fn check_boolean_except_clauses(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::Try(try_stmt) = stmt else { continue };
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
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s5714_flags_boolean_except_specifications() {
        let flagged = scan("try:\n    run()\nexcept (A or B):\n    stop()\n");
        assert_eq!(findings(&flagged, "python:S5714").len(), 1);
        let clean = "try:\n    run()\nexcept (A, B):\n    stop()\n";
        assert!(findings(&scan(clean), "python:S5714").is_empty());
    }
}
