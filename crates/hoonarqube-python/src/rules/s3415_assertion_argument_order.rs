use std::path::Path;

use hoonarqube_ir::Issue;
use ruff_python_ast::{CmpOp, Expr, ExprCall, ExprCompare, ModModule, Stmt, StmtAssert};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::TestScope;
use crate::support::child_bodies;
use crate::support::class_is_testcase_subclass;
use crate::support::flow_location;
use crate::support::for_each_expr;
use crate::support::is_expected_value;
use crate::support::is_pytest_file_name;
use crate::support::issue_at;
use crate::support::nth_argument_or_keyword;
use crate::support::self_method_name;
use crate::support::stmt_exprs;

const RULE_KEY: &str = "python:S3415";
const PYTEST_MESSAGE: &str =
    "Swap these 2 sides so they are in the correct order: actual value, expected value.";
const UNITTEST_MESSAGE: &str =
    "Swap these 2 arguments so they are in the correct order: actual value, expected value.";
const EXPECTED_FLOW: &str = "Expected value.";
const ACTUAL_FLOW: &str = "Actual value.";

/// Equality-assertion methods ordered as `first`/`second` arguments.
const EQUALITY_METHODS: [&str; 4] = [
    "assertEqual",
    "assertNotEqual",
    "assertAlmostEqual",
    "assertNotAlmostEqual",
];
/// Identity-assertion methods ordered as `expr1`/`expr2` arguments.
const IDENTITY_METHODS: [&str; 2] = ["assertIs", "assertIsNot"];

/// python:S3415 — assertion argument order. In test sources, an equality
/// assertion whose left operand is an expected value (a constant, a name
/// bound once to a constant, or `pytest.approx(<constant>)`) while the right
/// operand is not has the operands inverted; the same holds for unittest
/// equality and identity calls with a constant in the first slot.
pub(crate) fn check_s3415_assertion_argument_order(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    path: &Path,
) -> Vec<Issue> {
    let pytest_file = is_pytest_file_name(path);
    let module = parsed.syntax().body.as_slice();
    let mut issues = Vec::new();
    walk_s3415(
        module,
        module,
        pytest_file,
        &TestScope::root(),
        index,
        source,
        &mut issues,
    );
    issues
}

fn walk_s3415<'a>(
    stmts: &'a [Stmt],
    scope_stmts: &'a [Stmt],
    pytest_file: bool,
    scope: &TestScope<'a>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(function) => {
                let inner = scope.enter_function(function.name.as_str());
                let body = function.body.as_slice();
                walk_s3415(body, body, pytest_file, &inner, index, source, issues);
            }
            Stmt::ClassDef(class) => {
                let inner =
                    TestScope::enter_class(class.name.as_str(), class_is_testcase_subclass(class));
                walk_s3415(
                    class.body.as_slice(),
                    scope_stmts,
                    pytest_file,
                    &inner,
                    index,
                    source,
                    issues,
                );
            }
            other => {
                if let Stmt::Assert(assert) = other {
                    check_pytest_order(
                        assert,
                        scope_stmts,
                        pytest_file,
                        scope,
                        index,
                        source,
                        issues,
                    );
                }
                check_unittest_order(other, scope_stmts, scope, index, source, issues);
                for body in child_bodies(other) {
                    walk_s3415(body, scope_stmts, pytest_file, scope, index, source, issues);
                }
            }
        }
    }
}

/// Flags `assert expected == actual` inside pytest-style test functions.
fn check_pytest_order(
    assert: &StmtAssert,
    scope_stmts: &[Stmt],
    pytest_file: bool,
    scope: &TestScope,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if !scope.is_pytest_style_function(pytest_file) {
        return;
    }
    let Expr::Compare(compare) = assert.test.as_ref() else {
        return;
    };
    let Some(right) = single_equality_operand(compare) else {
        return;
    };
    let left = compare.left.as_ref();
    if !is_expected_value(left, scope_stmts) || is_expected_value(right, scope_stmts) {
        return;
    }
    let mut issue = issue_at(RULE_KEY, PYTEST_MESSAGE, compare.range(), index, source);
    issue.flows.push(hoonarqube_ir::IssueFlow {
        locations: vec![
            flow_location(EXPECTED_FLOW, left.range(), index, source),
            flow_location(ACTUAL_FLOW, right.range(), index, source),
        ],
    });
    issues.push(issue);
}

/// The right operand of a plain `left == right` comparison.
fn single_equality_operand(compare: &ExprCompare) -> Option<&Expr> {
    if compare.ops.len() == 1 && compare.ops[0] == CmpOp::Eq && compare.comparators.len() == 1 {
        return Some(&compare.comparators[0]);
    }
    None
}

/// Flags `self.assertEqual(<expected>, <actual>)` calls with inverted
/// argument order anywhere inside a `TestCase` class.
fn check_unittest_order(
    stmt: &Stmt,
    scope_stmts: &[Stmt],
    scope: &TestScope,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for expr in stmt_exprs(stmt) {
        for_each_expr(expr, &mut |candidate| {
            let Expr::Call(call) = candidate else {
                return;
            };
            if let Some(issue) = unittest_order_issue(call, scope_stmts, scope, index, source) {
                issues.push(issue);
            }
        });
    }
}

fn unittest_order_issue(
    call: &ExprCall,
    scope_stmts: &[Stmt],
    scope: &TestScope,
    index: &LineIndex,
    source: &str,
) -> Option<Issue> {
    if !scope.class_is_testcase {
        return None;
    }
    let (left_keyword, right_keyword) = ordered_argument_keywords(call)?;
    let arguments = &call.arguments;
    let first = nth_argument_or_keyword(arguments, 0, left_keyword)?;
    let second = nth_argument_or_keyword(arguments, 1, right_keyword)?;
    if !is_expected_value(first, scope_stmts) || is_expected_value(second, scope_stmts) {
        return None;
    }
    let mut issue = issue_at(RULE_KEY, UNITTEST_MESSAGE, call.range(), index, source);
    issue.flows.push(hoonarqube_ir::IssueFlow {
        locations: vec![
            flow_location(EXPECTED_FLOW, first.range(), index, source),
            flow_location(ACTUAL_FLOW, second.range(), index, source),
        ],
    });
    Some(issue)
}

/// The argument keyword pair for a `self.<method>` ordered-argument call.
fn ordered_argument_keywords(call: &ExprCall) -> Option<(&'static str, &'static str)> {
    if self_method_name(call, &EQUALITY_METHODS).is_some() {
        return Some(("first", "second"));
    }
    if self_method_name(call, &IDENTITY_METHODS).is_some() {
        return Some(("expr1", "expr2"));
    }
    None
}
