use crate::engine::file_context::FileContext;
use crate::support::for_each_stmt_expr;
use crate::support::for_each_stmt_in_scope;
use crate::support::is_none_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_inconsistent_returns(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::FunctionDef(function) = stmt else {
            continue;
        };
        if suite_contains_yield(&function.body) || function.body.is_empty() {
            continue;
        }
        let (valued, empty) = direct_return_kinds(&function.body);
        let falls_off_end = !matches!(function.body.last(), Some(Stmt::Return(_) | Stmt::Raise(_)));
        if valued > 0 && (empty > 0 || falls_off_end) {
            issues.push(issue_at(
                "python:S3801",
                "Make the return paths consistent; some paths return a value while others return None.",
                function.name.range(),
                index,
                source,
            ));
        }
    }
    issues
}

// --- python:S3801 — inconsistent return values --------------------------------

fn suite_contains_yield(suite: &[Stmt]) -> bool {
    let mut found = false;
    for_each_stmt_expr(suite, &mut |expr| {
        found |= matches!(expr, Expr::Yield(_) | Expr::YieldFrom(_));
    });
    found
}

fn direct_return_kinds(suite: &[Stmt]) -> (usize, usize) {
    let mut valued = 0;
    let mut empty = 0;
    for_each_stmt_in_scope(suite, &mut |stmt| {
        if let Stmt::Return(return_stmt) = stmt {
            match return_stmt.value.as_deref() {
                Some(value) if !is_none_literal(value) => valued += 1,
                _ => empty += 1,
            }
        }
    });
    (valued, empty)
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s3801_flags_method_with_inconsistent_returns() {
        let flagged = scan(
            "class C:\n    def m(self):\n        if x:\n            return 1\n        return\n",
        );
        assert!(!findings(&flagged, "python:S3801").is_empty());
    }

    #[test]
    fn s3801_module_function_still_flagged() {
        let flagged = scan("def f():\n    if x:\n        return 1\n    return\n");
        assert!(!findings(&flagged, "python:S3801").is_empty());
    }
}
