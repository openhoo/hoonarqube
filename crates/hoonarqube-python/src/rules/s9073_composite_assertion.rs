use std::path::Path;

use hoonarqube_ir::Issue;
use ruff_python_ast::{BoolOp, Expr, ModModule, Stmt, UnaryOp};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::TestScope;
use crate::support::child_bodies;
use crate::support::class_is_testcase_subclass;
use crate::support::is_pytest_file_name;
use crate::support::issue_at;

const RULE_KEY: &str = "python:S9073";
const MESSAGE: &str = "Split this composite assertion into separate assertions.";

/// python:S9073 — an assertion joining independent facts: an `and` chain
/// hides which operand failed, and `assert not (a or b)` is its De Morgan
/// equivalent. Plain `assert a or b` stays silent because splitting it
/// would change the meaning from "at least one holds" to "all hold"; the
/// same exclusion covers a top-level `or` with a nested `and`. The assert
/// statement anchors the finding. The reference check overrides catalog MAIN
/// scope with ALL: every assert in a pytest-named file is eligible, as are
/// function-body asserts within a unittest class on any path. Other production
/// assertions (including arbitrary `test*` functions) are not test contexts.
pub(crate) fn check_s9073_composite_assertion(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    path: &Path,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_s9073(
        &parsed.syntax().body,
        TestScope::root(),
        is_pytest_file_name(path),
        index,
        source,
        &mut issues,
    );
    issues
}

fn walk_s9073<'a>(
    stmts: &'a [Stmt],
    scope: TestScope<'a>,
    pytest_file: bool,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(function) => {
                let inner = scope.enter_function(function.name.as_str());
                walk_s9073(&function.body, inner, pytest_file, index, source, issues);
            }
            Stmt::ClassDef(class) => {
                let inner =
                    TestScope::enter_class(class.name.as_str(), class_is_testcase_subclass(class));
                walk_s9073(&class.body, inner, pytest_file, index, source, issues);
            }
            Stmt::Assert(assert) => {
                if (pytest_file || (scope.function.is_some() && scope.class_is_testcase))
                    && is_composite_assert(assert)
                {
                    issues.push(issue_at(RULE_KEY, MESSAGE, assert.range(), index, source));
                }
            }
            _ => {
                for body in child_bodies(stmt) {
                    walk_s9073(body, scope, pytest_file, index, source, issues);
                }
            }
        }
    }
}

fn is_composite_assert(assert: &ruff_python_ast::StmtAssert) -> bool {
    match assert.test.as_ref() {
        Expr::BoolOp(bool_op) => bool_op.op == BoolOp::And,
        Expr::UnaryOp(unary_op) => {
            unary_op.op == UnaryOp::Not
                && matches!(
                    unary_op.operand.as_ref(),
                    Expr::BoolOp(operand) if operand.op == BoolOp::Or
                )
        }
        _ => false,
    }
}
