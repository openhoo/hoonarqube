use ruff_python_ast::{Decorator, ExceptHandler, Expr, ModModule, Stmt, StmtExpr, StmtIf, StmtTry};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::support::{dotted_name_is, for_each_stmt, issue_at};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8994";
const MESSAGE: &str = "Pytest fixtures should contain at most one yield statement.";

/// python:S8994 — a `@pytest.fixture` function whose code paths can reach a
/// second `yield` fails at teardown with "fixture function has more than one
/// 'yield'", skipping the cleanup after it. The reference check counts yields
/// along each path: sequential statements accumulate, `if`/`elif`/`else` and
/// `try`/`except` branches merge as the maximum of the non-exiting branches
/// (a branch "exits" when any statement in it returns, raises, or contains an
/// `if` whose branches exit), `try`/`else`/`finally` run sequentially after
/// the merge, loop bodies count once and a loop `else` merges as a maximum,
/// and `with` bodies count sequentially. Yields inside nested functions,
/// classes, `match` cases, and non-statement positions (`x = yield`) are not
/// yield statements and stay silent. Every yield reached with a count of one
/// or more anchors its own finding on the yield statement.
pub(crate) fn check_s8994_pytest_fixture_single_yield(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::FunctionDef(function) = stmt else {
            return;
        };
        if !is_pytest_fixture(&function.decorator_list) {
            return;
        }
        let mut analyzer = YieldPathAnalyzer {
            violations: Vec::new(),
        };
        analyzer.analyze_statements(&function.body, 0);
        for range in analyzer.violations {
            issues.push(issue_at(RULE_KEY, MESSAGE, range, index, source));
        }
    });
    issues
}

/// Whether any decorator is `@pytest.fixture`, bare or called.
fn is_pytest_fixture(decorators: &[Decorator]) -> bool {
    decorators.iter().any(|decorator| {
        let expression = match &decorator.expression {
            Expr::Call(call) => call.func.as_ref(),
            expression => expression,
        };
        dotted_name_is(expression, "pytest.fixture")
    })
}

/// One analyzed branch: the yield count after it and whether it exits the
/// function (return/raise anywhere in the branch, per the reference's
/// any-branch heuristic).
struct BranchResult {
    yields_after: usize,
    exits: bool,
}

/// Mirrors the reference `YieldPathAnalyzer`: tracks the maximum number of
/// yield statements reachable on each path and records every yield statement
/// entered with a count of at least one.
struct YieldPathAnalyzer {
    violations: Vec<TextRange>,
}

impl YieldPathAnalyzer {
    fn analyze_statements(&mut self, stmts: &[Stmt], incoming: usize) -> usize {
        let mut count = incoming;
        for stmt in stmts {
            count = self.analyze_statement(stmt, count);
        }
        count
    }

    fn analyze_statement(&mut self, stmt: &Stmt, incoming: usize) -> usize {
        match stmt {
            Stmt::Expr(expr_stmt) if is_yield_statement(expr_stmt) => {
                if incoming >= 1 {
                    self.violations.push(stmt.range());
                }
                incoming + 1
            }
            Stmt::If(if_stmt) => self.analyze_if(if_stmt, incoming),
            Stmt::Try(try_stmt) => self.analyze_try(try_stmt, incoming),
            Stmt::For(for_stmt) => self.analyze_loop(&for_stmt.body, &for_stmt.orelse, incoming),
            Stmt::While(while_stmt) => {
                self.analyze_loop(&while_stmt.body, &while_stmt.orelse, incoming)
            }
            Stmt::With(with_stmt) => self.analyze_statements(&with_stmt.body, incoming),
            _ => incoming,
        }
    }

    /// `if`/`elif`/`else` chains are exclusive branches: the outcome is the
    /// maximum over the incoming count and every non-exiting branch.
    fn analyze_if(&mut self, if_stmt: &StmtIf, incoming: usize) -> usize {
        let mut results = Vec::with_capacity(if_stmt.elif_else_clauses.len() + 1);
        results.push(self.analyze_branch(&if_stmt.body, incoming));
        for clause in &if_stmt.elif_else_clauses {
            results.push(self.analyze_branch(&clause.body, incoming));
        }
        merge_branch_outcomes(incoming, &results)
    }

    /// `try`/`except` merge as exclusive branches; `else` and `finally` then
    /// run sequentially on the merged count.
    fn analyze_try(&mut self, try_stmt: &StmtTry, incoming: usize) -> usize {
        let mut results = Vec::with_capacity(try_stmt.handlers.len() + 1);
        results.push(self.analyze_branch(&try_stmt.body, incoming));
        for handler in &try_stmt.handlers {
            let ExceptHandler::ExceptHandler(handler) = handler;
            results.push(self.analyze_branch(&handler.body, incoming));
        }
        let mut count = merge_branch_outcomes(incoming, &results);
        count = self.analyze_statements(&try_stmt.orelse, count);
        self.analyze_statements(&try_stmt.finalbody, count)
    }

    /// A loop body contributes its yields once; a loop `else` merges as the
    /// maximum of the post-body count and the else path from the incoming
    /// count.
    fn analyze_loop(&mut self, body: &[Stmt], orelse: &[Stmt], incoming: usize) -> usize {
        let after_body = self.analyze_statements(body, incoming);
        if orelse.is_empty() {
            return after_body;
        }
        after_body.max(self.analyze_statements(orelse, incoming))
    }

    fn analyze_branch(&mut self, body: &[Stmt], incoming: usize) -> BranchResult {
        BranchResult {
            yields_after: self.analyze_statements(body, incoming),
            exits: branch_exits(body),
        }
    }
}

/// A `yield`/`yield from` expression statement — the only statement shape the
/// reference counts (`x = yield` and yields inside nested definitions are not
/// yield statements).
fn is_yield_statement(stmt: &StmtExpr) -> bool {
    matches!(stmt.value.as_ref(), Expr::Yield(_) | Expr::YieldFrom(_))
}

/// The merged outcome of exclusive branches: exiting branches contribute the
/// incoming count, non-exiting branches their own yield count.
fn merge_branch_outcomes(incoming: usize, results: &[BranchResult]) -> usize {
    let mut merged = incoming;
    for result in results {
        merged = if result.exits {
            merged.max(incoming)
        } else {
            merged.max(result.yields_after)
        };
    }
    merged
}

/// Whether any statement in the suite exits the function: a `return` or
/// `raise`, or an `if` whose body or any `elif`/`else` clause exits (the
/// reference's any-branch heuristic, not all-branches).
fn branch_exits(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|stmt| match stmt {
        Stmt::Return(_) | Stmt::Raise(_) => true,
        Stmt::If(if_stmt) => {
            branch_exits(&if_stmt.body)
                || if_stmt
                    .elif_else_clauses
                    .iter()
                    .any(|clause| branch_exits(&clause.body))
        }
        _ => false,
    })
}

#[cfg(test)]
mod tests {
    use crate::test_support::{findings, pos, scan_test_file};

    fn found(source: &str) -> Vec<hoonarqube_ir::Range> {
        findings(&scan_test_file(source), "python:S8994")
            .into_iter()
            .map(|issue| issue.range.clone())
            .collect()
    }

    #[test]
    fn s8994_flags_the_sonar_noncompliant_example() {
        // Sonar's Noncompliant example: two sequential yields; the second
        // anchors the finding (line 5, columns 4-12).
        let ranges = found(concat!(
            "import pytest\n",
            "\n",
            "@pytest.fixture\n",
            "def database_connection():\n",
            "    db = create_connection()\n",
            "    yield db\n",
            "    yield db\n",
            "    db.close()\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(7, 4));
        assert_eq!(ranges[0].end, pos(7, 12));
    }

    #[test]
    fn s8994_accepts_the_sonar_compliant_example() {
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "@pytest.fixture\n",
                "def database_connection():\n",
                "    db = create_connection()\n",
                "    yield db\n",
                "    db.close()\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8994_flags_every_yield_past_the_first_on_a_path() {
        // Three sequential yields flag the second and third; a fixture call
        // decorator counts the same as the bare form.
        let ranges = found(concat!(
            "import pytest\n",
            "\n",
            "@pytest.fixture(scope=\"module\")\n",
            "def resource():\n",
            "    yield 1\n",
            "    yield 2\n",
            "    yield 3\n",
        ));
        assert_eq!(ranges.len(), 2);
        assert_eq!(ranges[0].start, pos(6, 4));
        assert_eq!(ranges[1].start, pos(7, 4));
    }

    #[test]
    fn s8994_merges_exclusive_branches_and_exits() {
        // `if/else` yields on both branches: each branch starts at the
        // incoming count, so neither branch yield is second on its path; the
        // trailing yield after the merge is reached with count 1 and flags.
        let ranges = found(concat!(
            "import pytest\n",
            "\n",
            "@pytest.fixture\n",
            "def pick(cond):\n",
            "    if cond:\n",
            "        yield 1\n",
            "    else:\n",
            "        yield 2\n",
            "    yield 3\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(9, 4));
        assert_eq!(ranges[0].end, pos(9, 11));

        // A yield inside a branch entered with count 1 flags on that yield.
        let ranges = found(concat!(
            "import pytest\n",
            "\n",
            "@pytest.fixture\n",
            "def pick(cond):\n",
            "    yield 0\n",
            "    if cond:\n",
            "        yield 1\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(7, 8));

        // A branch that returns after yielding exits: the following yield is
        // the first on the surviving path and stays silent.
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "@pytest.fixture\n",
                "def pick(cond):\n",
                "    if cond:\n",
                "        yield 1\n",
                "        return\n",
                "    yield 2\n",
            ))
            .is_empty()
        );
    }

    #[test]
    fn s8994_counts_try_finally_and_loop_bodies() {
        // try + finally run sequentially: the finally yield is second.
        let ranges = found(concat!(
            "import pytest\n",
            "\n",
            "@pytest.fixture\n",
            "def resource():\n",
            "    try:\n",
            "        yield 1\n",
            "    finally:\n",
            "        yield 2\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(8, 8));

        // A yield inside a loop body counts once.
        let ranges = found(concat!(
            "import pytest\n",
            "\n",
            "@pytest.fixture\n",
            "def resource(items):\n",
            "    for item in items:\n",
            "        yield item\n",
            "    yield 2\n",
        ));
        assert_eq!(ranges.len(), 1);
        assert_eq!(ranges[0].start, pos(7, 4));
    }

    #[test]
    fn s8994_ignores_nested_functions_and_non_fixture_generators() {
        // Yields inside a nested function are not fixture yields; ordinary
        // generators without the fixture decorator stay silent, as do
        // non-yield expression statements and `x = yield` assignments.
        assert!(
            found(concat!(
                "import pytest\n",
                "\n",
                "@pytest.fixture\n",
                "def resource():\n",
                "    def inner():\n",
                "        yield 1\n",
                "        yield 2\n",
                "    yield 3\n",
                "\n",
                "def plain_generator():\n",
                "    yield 1\n",
                "    yield 2\n",
                "\n",
                "@pytest.fixture\n",
                "def assigned():\n",
                "    value = yield\n",
            ))
            .is_empty()
        );
    }
}
