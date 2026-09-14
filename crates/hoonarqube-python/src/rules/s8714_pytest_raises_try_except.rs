use hoonarqube_ir::{Issue, IssueFlow};
use ruff_python_ast::{ExceptHandler, Expr, ModModule, Stmt, StmtTry};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::support::dotted_name;
use crate::support::flow_location;
use crate::support::for_each_stmt;
use crate::support::issue_at;

const RULE_KEY: &str = "python:S8714";
const MESSAGE: &str = "Replace this try/except block with a \"pytest.raises\" context manager.";
const FLOW_MESSAGE: &str = "pytest.fail is called here.";

/// python:S8714 — a try/except in a test that marks the expected
/// exception with `pytest.fail` (as the last statement of the try body
/// or inside the `else` suite) re-implements `pytest.raises`: the
/// context manager fails when nothing raises and captures the exception
/// for the assertions. The whole try statement anchors the finding and
/// the `pytest.fail` call is the flow. Bare handlers name no exception
/// and have no `pytest.raises` equivalent.
pub(crate) fn check_s8714_pytest_raises_try_except(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        if let Stmt::Try(try_stmt) = stmt {
            check_try(try_stmt, index, source, &mut issues);
        }
    });
    issues
}

fn check_try(try_stmt: &StmtTry, index: &LineIndex, source: &str, issues: &mut Vec<Issue>) {
    if try_stmt.handlers.is_empty() {
        return;
    }
    let all_typed = try_stmt.handlers.iter().all(|handler| match handler {
        ExceptHandler::ExceptHandler(handler) => handler.type_.is_some(),
    });
    if !all_typed {
        return;
    }
    let Some(failure) = pytest_fail_statement(try_stmt) else {
        return;
    };
    let mut issue = issue_at(RULE_KEY, MESSAGE, try_stmt.range(), index, source);
    issue.flows.push(IssueFlow {
        locations: vec![flow_location(FLOW_MESSAGE, failure, index, source)],
    });
    issues.push(issue);
}

/// The `pytest.fail(...)` statement marking the expected exception: the
/// last statement of the try body, or any statement of the `else` suite.
fn pytest_fail_statement(try_stmt: &StmtTry) -> Option<TextRange> {
    if try_stmt.body.last().is_some_and(is_pytest_fail_statement) {
        return try_stmt.body.last().map(Ranged::range);
    }
    try_stmt
        .orelse
        .iter()
        .find(|stmt| is_pytest_fail_statement(stmt))
        .map(Ranged::range)
}

/// A bare expression statement calling `pytest.fail(...)`.
fn is_pytest_fail_statement(stmt: &Stmt) -> bool {
    let Stmt::Expr(statement) = stmt else {
        return false;
    };
    let Expr::Call(call) = statement.value.as_ref() else {
        return false;
    };
    dotted_name(&call.func).is_some_and(|path| path == "pytest.fail")
}
