use crate::engine::file_context::FileContext;
use crate::support::for_each_stmt_expr_in_scope;
use crate::support::for_each_stmt_in_scope;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
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
        // The reference bails out on CFGs with except/finally branching:
        // exceptional exits make return consistency undecidable.
        let mut has_try = false;
        for_each_stmt_in_scope(&function.body, &mut |inner| {
            has_try |= matches!(inner, Stmt::Try(_));
        });
        if has_try {
            continue;
        }
        let (valued, empty) = direct_return_kinds(&function.body);
        let falls_off_end = !function.body.last().is_some_and(stmt_always_exits);
        if valued > 0 && (empty > 0 || falls_off_end) {
            issues.push(issue_at(
                "python:S3801",
                "Refactor this function to use \"return\" consistently.",
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
    // `return <expr>` is valued even when the expression is `None`; only a
    // bare `return` is empty, matching the reference's hasValue check.
    let mut valued = 0;
    let mut empty = 0;
    for_each_stmt_in_scope(suite, &mut |stmt| {
        if let Stmt::Return(return_stmt) = stmt {
            match return_stmt.value.as_deref() {
                Some(_) => valued += 1,
                None => empty += 1,
            }
        }
    });
    (valued, empty)
}

/// Whether control provably cannot reach the statement following `stmt`.
/// Compound statements need every branch to terminate; a literal infinite
/// loop also cannot fall through when no possible break targets that loop.
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
        Stmt::While(while_stmt) => {
            matches!(while_stmt.test.as_ref(), Expr::BooleanLiteral(literal) if literal.value)
                && !suite_may_break_loop(&while_stmt.body)
        }
        Stmt::With(with_stmt) => with_stmt.body.last().is_some_and(stmt_always_exits),
        _ => false,
    }
}

// This is a conservative syntactic proof, not a reachability analysis. Even
// an unreachable break prevents the infinite-loop proof. Definitions isolate
// their control flow, and a nested loop's else suite belongs to the enclosing
// break scope, unlike that nested loop's body.
fn suite_may_break_loop(suite: &[Stmt]) -> bool {
    suite.iter().any(stmt_may_break_loop)
}

fn stmt_may_break_loop(stmt: &Stmt) -> bool {
    match stmt {
        // The caller retains the existing try bailout. Unsupported control
        // flow must never make the absence-of-break proof more permissive.
        Stmt::Break(_) | Stmt::Try(_) | Stmt::IpyEscapeCommand(_) => true,
        Stmt::If(if_stmt) => {
            suite_may_break_loop(&if_stmt.body)
                || if_stmt
                    .elif_else_clauses
                    .iter()
                    .any(|clause| suite_may_break_loop(&clause.body))
        }
        Stmt::For(for_stmt) => suite_may_break_loop(&for_stmt.orelse),
        Stmt::While(while_stmt) => suite_may_break_loop(&while_stmt.orelse),
        Stmt::With(with_stmt) => suite_may_break_loop(&with_stmt.body),
        Stmt::Match(match_stmt) => match_stmt
            .cases
            .iter()
            .any(|case| suite_may_break_loop(&case.body)),
        Stmt::FunctionDef(_)
        | Stmt::ClassDef(_)
        | Stmt::Return(_)
        | Stmt::Delete(_)
        | Stmt::TypeAlias(_)
        | Stmt::Assign(_)
        | Stmt::AugAssign(_)
        | Stmt::AnnAssign(_)
        | Stmt::Raise(_)
        | Stmt::Assert(_)
        | Stmt::Import(_)
        | Stmt::ImportFrom(_)
        | Stmt::Global(_)
        | Stmt::Nonlocal(_)
        | Stmt::Expr(_)
        | Stmt::Pass(_)
        | Stmt::Continue(_) => false,
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
        // The reference bails out on CFGs with except/finally branching, so
        // a function containing try/except is never flagged.
        let swallowing_handler =
            scan("def g():\n    try:\n        return read()\n    except OSError:\n        pass\n");
        assert!(findings(&swallowing_handler, "python:S3801").is_empty());
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

    #[test]
    fn s3801_literal_true_callable_tails_do_not_fall_through() {
        for source in [
            "def choose(flag):\n    while True:\n        if flag:\n            return 1\n",
            "class Engine:\n    def choose(self, flag):\n        while True:\n            if flag:\n                return 1\n",
            "async def poll(ready):\n    while True:\n        if ready:\n            return 9\n",
        ] {
            assert_eq!(findings(&scan(source), "python:S3801").len(), 0, "{source}");
        }
    }

    #[test]
    fn s3801_nested_loop_body_break_does_not_exit_outer_loop() {
        let source = "def choose(items, ready):\n    while True:\n        for item in items:\n            if item:\n                break\n        if ready:\n            return 1\n";
        assert_eq!(findings(&scan(source), "python:S3801").len(), 0, "{source}");
    }

    #[test]
    fn s3801_nested_function_break_does_not_exit_outer_loop() {
        let source = "def choose(flag):\n    while True:\n        def helper(items):\n            for item in items:\n                break\n        if flag:\n            return 1\n";
        assert_eq!(findings(&scan(source), "python:S3801").len(), 0, "{source}");
    }

    #[test]
    fn s3801_literal_true_explicit_none_is_valued() {
        let source = "def choose(flag):\n    while True:\n        if flag:\n            return 1\n        return None\n";
        assert_eq!(findings(&scan(source), "python:S3801").len(), 0, "{source}");
    }

    #[test]
    fn s3801_finite_and_unknown_loops_keep_implicit_return() {
        for source in [
            "def choose(flag):\n    while flag:\n        if ready:\n            return 1\n",
            "def choose(flag):\n    while False:\n        if flag:\n            return 1\n",
            "def choose(items):\n    for item in items:\n        if item:\n            return 1\n",
        ] {
            assert_eq!(findings(&scan(source), "python:S3801").len(), 1, "{source}");
        }
    }

    #[test]
    fn s3801_reachable_outer_breaks_keep_implicit_return() {
        for source in [
            "def choose(flag):\n    while True:\n        if flag:\n            return 1\n        break\n",
            "def choose(stop, ready):\n    while True:\n        if stop:\n            break\n        if ready:\n            return 1\n",
            "def choose(stop, ready, lock):\n    while True:\n        with lock:\n            if stop:\n                break\n        if ready:\n            return 1\n",
        ] {
            assert_eq!(findings(&scan(source), "python:S3801").len(), 1, "{source}");
        }
    }

    #[test]
    fn s3801_nested_loop_else_breaks_exit_enclosing_loop() {
        for source in [
            "def choose(items):\n    while True:\n        for item in items:\n            break\n        else:\n            break\n        return 1\n",
            "def choose(inner):\n    while True:\n        while inner:\n            break\n        else:\n            break\n        return 1\n",
        ] {
            assert_eq!(findings(&scan(source), "python:S3801").len(), 1, "{source}");
        }
    }

    #[test]
    fn s3801_literal_true_bare_return_stays_inconsistent() {
        for source in [
            "def choose(flag):\n    while True:\n        if flag:\n            return 1\n        return\n",
            "def choose(flag):\n    if flag:\n        return 1\n    return\n",
        ] {
            assert_eq!(findings(&scan(source), "python:S3801").len(), 1, "{source}");
        }
    }

    #[test]
    fn s3801_existing_clean_functions_remain_clean() {
        for source in [
            "def spin():\n    while True:\n        pass\n",
            "def choose(flag):\n    if flag:\n        return 1\n    return 2\n",
        ] {
            assert_eq!(findings(&scan(source), "python:S3801").len(), 0, "{source}");
        }
    }

    #[test]
    fn s3801_loop_proof_preserves_exception_generator_and_uncertain_breaks() {
        for source in [
            "def choose(flag):\n    while True:\n        try:\n            if flag:\n                return 1\n        except OSError:\n            break\n",
            "def choose(flag):\n    while True:\n        yield 1\n        if flag:\n            return 1\n",
        ] {
            assert!(
                findings(&scan(source), "python:S3801").is_empty(),
                "{source}"
            );
        }
        // The bounded proof conservatively retains a syntactic break even
        // after a return: it does not introduce general reachability analysis.
        let conservative =
            scan("def choose():\n    while True:\n        return 1\n        break\n");
        assert_eq!(findings(&conservative, "python:S3801").len(), 1);
    }
}
