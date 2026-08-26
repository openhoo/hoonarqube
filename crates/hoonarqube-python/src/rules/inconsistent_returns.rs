use crate::engine::file_context::FileContext;
use crate::support::child_bodies;
use crate::support::for_each_stmt_expr_in_scope;
use crate::support::for_each_stmt_in_scope;
use crate::support::is_none_literal;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

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
        let falls_off_end = !function.body.last().is_some_and(stmt_always_exits);
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
    for_each_stmt_expr_in_scope(suite, &mut |expr| {
        found |= matches!(expr, Expr::Yield(_) | Expr::YieldFrom(_));
    });
    found
}

fn direct_return_kinds(suite: &[Stmt]) -> (usize, usize) {
    // Returns inside except handlers resolve exceptional outcomes; they feed
    // exit analysis below but stay out of the normal-path return census.
    let mut handler_ranges: Vec<TextRange> = Vec::new();
    collect_except_handler_ranges(suite, &mut handler_ranges);
    let mut valued = 0;
    let mut empty = 0;
    for_each_stmt_in_scope(suite, &mut |stmt| {
        if let Stmt::Return(return_stmt) = stmt {
            let in_handler = handler_ranges.iter().any(|range| {
                range.start() <= return_stmt.start() && return_stmt.end() <= range.end()
            });
            if !in_handler {
                match return_stmt.value.as_deref() {
                    Some(value) if !is_none_literal(value) => valued += 1,
                    _ => empty += 1,
                }
            }
        }
    });
    (valued, empty)
}

/// Ranges of every `except` clause under `suite`, nested compounds included.
fn collect_except_handler_ranges(suite: &[Stmt], out: &mut Vec<TextRange>) {
    for stmt in suite {
        if let Stmt::Try(try_stmt) = stmt {
            for handler in &try_stmt.handlers {
                out.push(handler.range());
            }
        }
        for body in child_bodies(stmt) {
            collect_except_handler_ranges(body, out);
        }
    }
}

/// Whether control provably leaves `stmt` through a `return`/`raise`
/// without falling through: compound statements terminate only when every
/// branch terminates, loops may run zero iterations, and plain statements
/// fall through.
fn stmt_always_exits(stmt: &Stmt) -> bool {
    match stmt {
        Stmt::Return(_) | Stmt::Raise(_) => true,
        Stmt::If(if_stmt) => {
            // An if-chain exits only when terminated by an `else` clause and
            // every arm's last statement exits.
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
            // `finally` runs regardless of how the try block is left, so it
            // says nothing about exiting via return/raise.
            try_stmt.body.last().is_some_and(stmt_always_exits)
                && try_stmt.handlers.iter().all(|handler| match handler {
                    ExceptHandler::ExceptHandler(handler) => {
                        handler.body.last().is_some_and(stmt_always_exits)
                    }
                })
                && (try_stmt.orelse.is_empty()
                    || try_stmt.orelse.last().is_some_and(stmt_always_exits))
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
        Stmt::With(with_stmt) => with_stmt.body.last().is_some_and(stmt_always_exits),
        _ => false,
    }
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

    #[test]
    fn s3801_all_returning_compound_tails_stay_clean() {
        let if_else =
            scan("def fetch(flag):\n    if flag:\n        return 5\n    else:\n        return 0\n");
        assert!(findings(&if_else, "python:S3801").is_empty());
        let try_except = scan(
            "def load():\n    try:\n        return read()\n    except OSError:\n        return None\n",
        );
        assert!(findings(&try_except, "python:S3801").is_empty());
        let matched = scan(
            "def route(cmd):\n    match cmd:\n        case \"go\":\n            return 1\n        case _:\n            return 0\n",
        );
        assert!(findings(&matched, "python:S3801").is_empty());
        let guarded_match = scan(
            "def route(cmd, cond):\n    match cmd:\n        case _ if cond:\n            return 1\n        case _:\n            return 0\n",
        );
        assert!(findings(&guarded_match, "python:S3801").is_empty());
        let nested_if_else = scan(
            "def deep(flag):\n    if flag:\n        if flag:\n            return 1\n        else:\n            return 2\n    else:\n        return 3\n",
        );
        assert!(findings(&nested_if_else, "python:S3801").is_empty());
    }

    #[test]
    fn s3801_partial_compound_tails_stay_flagged() {
        let missing_else = scan("def f(flag):\n    if flag:\n        return 5\n");
        assert!(!findings(&missing_else, "python:S3801").is_empty());
        let swallowing_handler =
            scan("def g():\n    try:\n        return read()\n    except OSError:\n        pass\n");
        assert!(!findings(&swallowing_handler, "python:S3801").is_empty());
    }

    #[test]
    fn s3801_nested_generator_does_not_exempt_function() {
        let flagged = scan(
            "def f(flag):\n    def gen():\n        yield 1\n    if flag:\n        return 1\n    return\n",
        );
        assert!(!findings(&flagged, "python:S3801").is_empty());
        let generator_itself = scan("def h(flag):\n    yield 1\n    if flag:\n        return 1\n");
        assert!(findings(&generator_itself, "python:S3801").is_empty());
    }
}
