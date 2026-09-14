use std::path::Path;

use hoonarqube_ir::Issue;
use ruff_python_ast::{CmpOp, Expr, ModModule, Stmt, StmtAssert};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::TestScope;
use crate::support::child_bodies;
use crate::support::class_is_testcase_subclass;
use crate::support::exprs_textually_equal;
use crate::support::flow_location;
use crate::support::for_each_expr;
use crate::support::is_pytest_file_name;
use crate::support::issue_at;
use crate::support::nth_argument_or_keyword;
use crate::support::self_method_name;
use crate::support::stmt_exprs;

const RULE_KEY: &str = "python:S5863";
const MESSAGE: &str = "Replace this assertion to not have the same actual and expected expression.";
const ACTUAL_FLOW: &str = "This is the same expression as the expected argument.";

/// Equality-assertion methods ordered as `first`/`second` arguments.
const EQUALITY_METHODS: [&str; 4] = [
    "assertEqual",
    "assertNotEqual",
    "assertAlmostEqual",
    "assertNotAlmostEqual",
];
/// Identity-assertion methods ordered as `expr1`/`expr2` arguments.
const IDENTITY_METHODS: [&str; 2] = ["assertIs", "assertIsNot"];

/// python:S5863 — assertions should not be given twice the same argument.
/// In test sources, a pytest-style `assert x == x` (or `!=`) and unittest
/// equality or identity calls with one argument repeated compare an
/// expression with itself.
pub(crate) fn check_s5863_identical_assertion_arguments(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    path: &Path,
) -> Vec<Issue> {
    let pytest_file = is_pytest_file_name(path);
    let module = parsed.syntax().body.as_slice();
    let mut issues = Vec::new();
    walk_s5863(
        module,
        pytest_file,
        &TestScope::root(),
        index,
        source,
        &mut issues,
    );
    issues
}

fn walk_s5863<'a>(
    stmts: &'a [Stmt],
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
                walk_s5863(
                    function.body.as_slice(),
                    pytest_file,
                    &inner,
                    index,
                    source,
                    issues,
                );
            }
            Stmt::ClassDef(class) => {
                let inner =
                    TestScope::enter_class(class.name.as_str(), class_is_testcase_subclass(class));
                walk_s5863(
                    class.body.as_slice(),
                    pytest_file,
                    &inner,
                    index,
                    source,
                    issues,
                );
            }
            other => {
                if let Stmt::Assert(assert) = other {
                    check_pytest_identical(assert, pytest_file, scope, index, source, issues);
                }
                check_unittest_identical(other, scope, index, source, issues);
                for body in child_bodies(other) {
                    walk_s5863(body, pytest_file, scope, index, source, issues);
                }
            }
        }
    }
}

/// Flags `assert x == x` / `assert x != x` in pytest-style test functions.
fn check_pytest_identical(
    assert: &StmtAssert,
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
    if compare.ops.len() != 1 || compare.comparators.len() != 1 {
        return;
    }
    if !matches!(compare.ops[0], CmpOp::Eq | CmpOp::NotEq) {
        return;
    }
    report_identical(
        compare.left.as_ref(),
        &compare.comparators[0],
        index,
        source,
        issues,
    );
}

/// Flags unittest equality and identity calls with identical arguments.
fn check_unittest_identical(
    stmt: &Stmt,
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
            if !scope.class_is_testcase {
                return;
            }
            let keywords = if self_method_name(call, &EQUALITY_METHODS).is_some() {
                ("first", "second")
            } else if self_method_name(call, &IDENTITY_METHODS).is_some() {
                ("expr1", "expr2")
            } else {
                return;
            };
            let arguments = &call.arguments;
            let (Some(first), Some(second)) = (
                nth_argument_or_keyword(arguments, 0, keywords.0),
                nth_argument_or_keyword(arguments, 1, keywords.1),
            ) else {
                return;
            };
            report_identical(first, second, index, source, issues);
        });
    }
}

/// Emits the finding when actual and expected are the same expression; the
/// expected (right) side anchors the finding, the actual side the flow.
fn report_identical(
    actual: &Expr,
    expected: &Expr,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if !exprs_textually_equal(actual, expected, source) {
        return;
    }
    let mut issue = issue_at(RULE_KEY, MESSAGE, expected.range(), index, source);
    issue.flows.push(hoonarqube_ir::IssueFlow {
        locations: vec![flow_location(ACTUAL_FLOW, actual.range(), index, source)],
    });
    issues.push(issue);
}
