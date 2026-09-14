use std::path::Path;

use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::support::dotted_name_is;
use crate::support::for_each_stmt;
use crate::support::is_pytest_file_name;
use crate::support::issue_at;

const RULE_KEY: &str = "python:S9001";
const MESSAGE: &str = "Provide a reason for marking this test as expected to fail.";

/// python:S9001 — an `@pytest.mark.xfail` marker without a `reason`
/// keyword leaves the expected failure undocumented; the reason must
/// live on the marker itself, so comments and docstrings do not
/// satisfy the rule. The decorator anchors the finding, spanning the
/// leading `@` like Sonar's decorator range.
pub(crate) fn check_s9001_xfail_reason(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    path: &Path,
) -> Vec<Issue> {
    if !is_pytest_file_name(path) {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::FunctionDef(function) = stmt else {
            return;
        };
        for decorator in &function.decorator_list {
            check_decorator(
                &decorator.expression,
                decorator.range(),
                index,
                source,
                &mut issues,
            );
        }
    });
    issues
}

/// The `pytest.mark.xfail` marker of one decorator, ignoring a
/// call-wrapper but rejecting markers that carry `reason`. `range`
/// is the whole decorator syntax including the leading `@`, matching
/// Sonar's decorator anchor.
fn check_decorator(
    expression: &Expr,
    range: TextRange,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let mut marker = expression;
    if let Expr::Call(call) = expression {
        if call.arguments.keywords.iter().any(|keyword| {
            keyword
                .arg
                .as_ref()
                .is_some_and(|arg| arg.as_str() == "reason")
        }) {
            return;
        }
        marker = &call.func;
    }
    if !dotted_name_is(marker, "pytest.mark.xfail") {
        return;
    }
    issues.push(issue_at(RULE_KEY, MESSAGE, range, index, source));
}
