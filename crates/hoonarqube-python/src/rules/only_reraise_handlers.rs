use crate::engine::file_context::FileContext;
use crate::support::issue_at;
use hoonarqube_ir::Issue;
use ruff_python_ast::ExceptHandler;
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

// --- python:S2737 — except clause that only re-raises -------------------------

pub(crate) fn check_only_reraise_handlers(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for stmt in &file_ctx.stmts {
        let Stmt::Try(try_stmt) = stmt else { continue };
        // Sonar's ExceptRethrowingCheck only inspects the LAST except
        // clause — earlier handlers stay silent because a re-raise there
        // can deliberately shield the broader handlers below.
        let Some(handler) = try_stmt.handlers.last() else {
            continue;
        };
        let ExceptHandler::ExceptHandler(inner) = handler;
        // Only a raise in FIRST position counts: preceding statements mean
        // the clause does real work before propagating.
        let Some(Stmt::Raise(raised)) = inner.body.first() else {
            continue;
        };
        // A bare `raise` always re-raises. `raise <name>` only re-raises
        // when <name> is the instance bound by `except ... as <name>` —
        // raising the caught type again builds a NEW exception instead.
        let pure_reraise = match raised.exc.as_deref() {
            None => true,
            Some(Expr::Name(name)) => inner.name.as_ref().is_some_and(|bound| bound.id == name.id),
            Some(_) => false,
        };
        if pure_reraise {
            issues.push(issue_at(
                "python:S2737",
                "Remove this 'except' clause or handle the exception; it only re-raises.",
                raised.range(),
                index,
                source,
            ));
        }
    }
    issues
}

#[cfg(test)]
mod tests {

    use crate::test_support::{findings, scan};

    #[test]
    fn s2737_flags_handlers_that_only_reraise() {
        let flagged = scan("try:\n    risky()\nexcept ValueError:\n    raise\n");
        assert_eq!(findings(&flagged, "python:S2737").len(), 1);
        let clean = "try:\n    risky()\nexcept ValueError:\n    log()\n    raise\n";
        assert!(findings(&scan(clean), "python:S2737").is_empty());
    }

    #[test]
    fn s2737_ignores_reraise_in_non_last_handler() {
        // Issue #615: Sonar's ExceptRethrowingCheck only inspects the LAST
        // except clause; a non-last re-raise may deliberately shield the
        // broader handlers below (django admin/views/main.py:490).
        let report =
            scan("try:\n    f()\nexcept ValueError:\n    raise\nexcept TypeError:\n    handle()\n");
        assert!(findings(&report, "python:S2737").is_empty());
    }

    #[test]
    fn s2737_flags_reraise_in_last_handler_only() {
        let report =
            scan("try:\n    f()\nexcept ValueError:\n    raise\nexcept TypeError:\n    raise\n");
        let found = findings(&report, "python:S2737");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 6);
    }

    #[test]
    fn s2737_flags_raise_of_bound_instance() {
        // Sonar flags `raise e` when e is bound by `except ... as e`,
        // including parenthesized and `raise e from x` forms.
        for source in [
            "try:\n    f()\nexcept ValueError as e:\n    raise e\n",
            "try:\n    f()\nexcept ValueError as e:\n    raise (e)\n",
            "try:\n    f()\nexcept ValueError as e:\n    raise e from x\n",
            "try:\n    f()\nexcept (ValueError, TypeError) as e:\n    raise e\n",
        ] {
            assert_eq!(findings(&scan(source), "python:S2737").len(), 1, "{source}");
        }
    }

    #[test]
    fn s2737_ignores_raise_of_new_or_unbound_exception() {
        // Raising the caught type again builds a NEW exception instance;
        // Sonar only flags re-raising the bound `as` instance.
        for source in [
            "try:\n    f()\nexcept ValueError:\n    raise ValueError\n",
            "try:\n    f()\nexcept ValueError:\n    raise TypeError\n",
            "try:\n    f()\nexcept ValueError as e:\n    raise other\n",
            "try:\n    f()\nexcept ValueError as e:\n    raise Wrapper(e) from e\n",
            "try:\n    f()\nexcept ValueError as e:\n    raise e.attr\n",
        ] {
            assert!(
                findings(&scan(source), "python:S2737").is_empty(),
                "{source}"
            );
        }
    }

    #[test]
    fn s2737_flags_leading_raise_even_with_dead_tail() {
        // Sonar inspects the FIRST body statement only; a raise in first
        // position is flagged even when dead statements follow.
        let report = scan("try:\n    f()\nexcept ValueError:\n    raise\n    log()\n");
        assert_eq!(findings(&report, "python:S2737").len(), 1);
    }

    #[test]
    fn s2737_reports_raise_statement_range() {
        let report = scan("try:\n    f()\nexcept ValueError:\n    raise\n");
        let found = findings(&report, "python:S2737");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 4);
        assert_eq!(found[0].range.end.line, 4);
    }
}
