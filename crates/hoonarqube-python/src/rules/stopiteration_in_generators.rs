use crate::engine::file_context::FileContext;
use crate::support::{child_bodies, issue_at, stmt_exprs};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, Stmt};
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const RULE_KEY: &str = "python:S8493";
const MESSAGE: &str = "Replace this \"raise StopIteration\" with a \"return\" statement.";

/// python:S8493 — PEP 479 converts a `StopIteration` raised inside a
/// generator into a `RuntimeError` (Python 3.7+); `return` is the proper
/// way to terminate one. Scope `MAIN`.
///
/// Mirrors `StopIterationInGeneratorCheck`: a `raise` whose first
/// expression is `StopIteration` or `StopIteration(...)` is flagged when
/// its nearest enclosing function contains a `yield`/`yield from` in its
/// own scope — nested function bodies do not count, but class bodies do
/// (the reference's `ReturnStmtCollector` skips nested `FunctionDef`s, not
/// `ClassDef`s). `raise StopIteration() from cause` is flagged; raising
/// other exceptions, or `StopIteration` outside a generator, stays silent.
/// The issue anchors on the `raise` statement.
pub(crate) fn check_stopiteration_in_generators(
    index: &LineIndex,
    source: &str,
    file_ctx: &FileContext,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for function in &file_ctx.functions {
        if !contains_yield(&function.body) {
            continue;
        }
        collect_raises(&function.body, index, source, &mut issues);
    }
    issues
}

/// Whether the function's own scope contains a `yield`/`yield from`:
/// nested function bodies are skipped, class bodies are not.
fn contains_yield(body: &[Stmt]) -> bool {
    let mut pending: Vec<&Stmt> = body.iter().collect();
    while let Some(stmt) = pending.pop() {
        if matches!(stmt, Stmt::FunctionDef(_)) {
            continue;
        }
        for expr in stmt_exprs(stmt) {
            let mut found = false;
            crate::support::for_each_expr(expr, &mut |node| {
                found |= matches!(node, Expr::Yield(_) | Expr::YieldFrom(_));
            });
            if found {
                return true;
            }
        }
        for suite in child_bodies(stmt) {
            pending.extend(suite.iter());
        }
    }
    false
}

/// Flags `raise StopIteration` statements in the function's own scope:
/// nested function bodies are skipped, class bodies are not.
fn collect_raises(body: &[Stmt], index: &LineIndex, source: &str, issues: &mut Vec<Issue>) {
    let mut pending: Vec<&Stmt> = body.iter().collect();
    while let Some(stmt) = pending.pop() {
        if matches!(stmt, Stmt::FunctionDef(_)) {
            continue;
        }
        if let Stmt::Raise(raise) = stmt
            && raise.exc.as_deref().is_some_and(is_stop_iteration)
        {
            issues.push(issue_at(RULE_KEY, MESSAGE, raise.range(), index, source));
        }
        for suite in child_bodies(stmt) {
            pending.extend(suite.iter());
        }
    }
}

/// Whether the raised expression is `StopIteration` or `StopIteration(...)`.
fn is_stop_iteration(expr: &Expr) -> bool {
    match expr {
        Expr::Name(name) => name.id.as_str() == "StopIteration",
        Expr::Call(call) => {
            matches!(call.func.as_ref(), Expr::Name(name) if name.id.as_str() == "StopIteration")
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, scan};

    const KEY: &str = "python:S8493";

    /// Sonar's own pair: `raise StopIteration` inside a generator is
    /// flagged; terminating with `return` is clean.
    #[test]
    fn s8493_flags_sonar_example() {
        let flagged = scan(concat!(
            "def my_generator():\n",
            "    yield 1\n",
            "    yield 2\n",
            "    raise StopIteration\n",
        ));
        let hits = findings(&flagged, KEY);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].range.start.line, 4);
        let clean = scan(concat!(
            "def my_generator():\n",
            "    yield 1\n",
            "    yield 2\n",
            "    return\n",
        ));
        assert!(findings(&clean, KEY).is_empty());
    }

    /// Call forms, `from` causes, and nested conditional positions flag;
    /// non-generators, nested functions, and other exceptions stay silent.
    #[test]
    fn s8493_forms_and_boundaries() {
        let report = scan(concat!(
            "def gen():\n",
            "    yield 1\n",
            "    if done:\n",
            "        raise StopIteration()\n",
            "    raise StopIteration() from err\n",
        ));
        assert_eq!(findings(&report, KEY).len(), 2);
        let clean = scan(concat!(
            "def plain():\n",
            "    raise StopIteration\n",
            "\n",
            "def outer():\n",
            "    yield 1\n",
            "    def inner():\n",
            "        raise StopIteration\n",
            "\n",
            "def gen2():\n",
            "    yield 1\n",
            "    raise ValueError\n",
        ));
        assert!(findings(&clean, KEY).is_empty());
    }
}
