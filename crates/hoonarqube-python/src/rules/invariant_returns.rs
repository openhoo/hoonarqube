use crate::engine::file_context::FileContext;
use crate::support::constant_truth;
use crate::support::expr_normalized_text;
use crate::support::for_each_stmt_in_scope;
use crate::support::is_none_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

pub(crate) fn check_invariant_returns(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        if let Stmt::FunctionDef(function) = stmt {
            // The reference requires every exit path to return the same
            // value: at least two returns, no implicit fall-off-the-end, and
            // identical non-None constant expressions.
            let returns = direct_constant_return_texts(&function.body, source);
            let all_returns = count_returns(&function.body);
            let falls_off = !function.body.last().is_some_and(stmt_always_exits);
            let identical = returns.len() >= 2
                && returns.len() == all_returns
                && !falls_off
                && returns.windows(2).all(|pair| pair[0] == pair[1]);
            if identical {
                issues.push(issue_at(
                    "python:S3516",
                    "Refactor this method to not always return the same value.",
                    function.name.range(),
                    index,
                    source,
                ));
            }
        }
    }
    issues
}

// --- python:S3516 — invariant function returns --------------------------------

fn count_returns(suite: &[Stmt]) -> usize {
    let mut count = 0;
    for_each_stmt_in_scope(suite, &mut |stmt| {
        if matches!(stmt, Stmt::Return(_)) {
            count += 1;
        }
    });
    count
}

/// Whether control provably leaves `stmt` via return/raise on every path.
fn stmt_always_exits(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Return(_) | Stmt::Raise(_) => true,
        Stmt::If(if_stmt) => {
            if_stmt
                .elif_else_clauses
                .last()
                .is_some_and(|clause| clause.test.is_none())
                && if_stmt.body.last().is_some_and(stmt_always_exits)
                && if_stmt
                    .elif_else_clauses
                    .iter()
                    .all(|clause| clause.body.last().is_some_and(stmt_always_exits))
        }
        Stmt::Try(try_stmt) => {
            try_stmt.body.last().is_some_and(stmt_always_exits)
                && try_stmt.handlers.iter().all(|handler| match handler {
                    ruff_python_ast::ExceptHandler::ExceptHandler(handler) => {
                        handler.body.last().is_some_and(stmt_always_exits)
                    }
                })
        }
        Stmt::Match(match_stmt) => {
            !match_stmt.cases.is_empty()
                && match_stmt
                    .cases
                    .iter()
                    .all(|case| case.body.last().is_some_and(stmt_always_exits))
                && match_stmt
                    .cases
                    .last()
                    .is_some_and(|case| case.guard.is_none() && case.pattern.is_irrefutable())
        }
        _ => false,
    }
}

/// Normalized texts of direct non-None constant `return` values.
fn direct_constant_return_texts(suite: &[Stmt], source: &str) -> Vec<String> {
    let mut texts = Vec::new();
    for_each_stmt_in_scope(suite, &mut |stmt| {
        if let Stmt::Return(return_stmt) = stmt
            && let Some(value) = return_stmt.value.as_deref()
            && !is_none_literal(value)
            && constant_truth(value).is_some()
        {
            texts.push(expr_normalized_text(value, source));
        }
    });
    texts
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    #[test]
    fn s3516_flags_method_with_invariant_returns() {
        let flagged = scan("class C:\n    def m(self):\n        return 1\n        return 1\n");
        assert!(!findings(&flagged, "python:S3516").is_empty());
    }

    #[test]
    fn s3516_module_function_still_flagged() {
        let flagged = scan("def f():\n    return 1\n    return 1\n");
        assert!(!findings(&flagged, "python:S3516").is_empty());
    }
}
