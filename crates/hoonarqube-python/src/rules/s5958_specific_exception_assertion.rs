use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ExprCall, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::TestScope;
use crate::support::child_bodies;
use crate::support::class_is_testcase_subclass;
use crate::support::dotted_name;
use crate::support::for_each_expr;
use crate::support::issue_at;
use crate::support::keyword_value;
use crate::support::nth_argument_or_keyword;
use crate::support::self_method_name;
use crate::support::stmt_exprs;

const RULE_KEY: &str = "python:S5958";
const MESSAGE: &str = "This assertion is too broad; use a more specific exception type or check the exception message.";

/// unittest methods asserting raised exceptions. Regex variants always
/// check the message and never report.
const UNITTEST_RAISE_METHODS: [&str; 3] =
    ["assertRaises", "assertRaisesRegex", "assertRaisesRegexp"];

/// Broad exception types, matched textually (types and type calls).
const BROAD_EXCEPTIONS: [&str; 4] = [
    "Exception",
    "BaseException",
    "builtins.Exception",
    "builtins.BaseException",
];

/// python:S5958 — tests should check which exception is thrown. A
/// `pytest.raises` or unittest `assertRaises` argument of `Exception` or
/// `BaseException` matches any failure, including unrelated setup errors.
pub(crate) fn check_s5958_specific_exception_assertion(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_s5958(
        parsed.syntax().body.as_slice(),
        &TestScope::root(),
        index,
        source,
        &mut issues,
    );
    issues
}

fn walk_s5958<'a>(
    stmts: &'a [Stmt],
    scope: &TestScope<'a>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(function) => {
                let inner = scope.enter_function(function.name.as_str());
                walk_s5958(function.body.as_slice(), &inner, index, source, issues);
            }
            Stmt::ClassDef(class) => {
                let inner =
                    TestScope::enter_class(class.name.as_str(), class_is_testcase_subclass(class));
                walk_s5958(class.body.as_slice(), &inner, index, source, issues);
            }
            // With items are checked here so the generic expression walk
            // never double-reports them.
            Stmt::With(with_stmt) => {
                for item in &with_stmt.items {
                    check_with_item(item, scope, index, source, issues);
                }
                walk_s5958(with_stmt.body.as_slice(), scope, index, source, issues);
            }
            other => walk_s5958_expression_bearing(other, scope, index, source, issues),
        }
    }
}

/// Checks one with-item context expression for a broad raises assertion.
fn check_with_item(
    item: &ruff_python_ast::WithItem,
    scope: &TestScope,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    if let Expr::Call(call) = &item.context_expr {
        check_broad_assertion(call, scope, index, source, issues);
    }
}

/// Walks one statement's own expressions and nested statement lists.
fn walk_s5958_expression_bearing(
    stmt: &Stmt,
    scope: &TestScope,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for expr in stmt_exprs(stmt) {
        for_each_expr(expr, &mut |candidate| {
            if let Expr::Call(call) = candidate {
                check_broad_assertion(call, scope, index, source, issues);
            }
        });
    }
    for body in child_bodies(stmt) {
        walk_s5958(body, scope, index, source, issues);
    }
}

/// Reports the exception argument when the assertion covers every failure.
fn check_broad_assertion(
    call: &ExprCall,
    scope: &TestScope,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let Some(exception) = broad_exception_argument(call, scope) else {
        return;
    };
    issues.push(issue_at(
        RULE_KEY,
        MESSAGE,
        exception.range(),
        index,
        source,
    ));
}

/// The overly broad exception argument of a raises assertion, if any.
fn broad_exception_argument<'a>(call: &'a ExprCall, scope: &TestScope) -> Option<&'a Expr> {
    if dotted_name(&call.func).as_deref() == Some("pytest.raises") {
        if keyword_value(&call.arguments, "match").is_some() {
            return None;
        }
        return broad_argument(nth_argument_or_keyword(
            &call.arguments,
            0,
            "expected_exception",
        )?);
    }
    if scope.class_is_testcase
        && self_method_name(call, &UNITTEST_RAISE_METHODS) == Some("assertRaises")
    {
        return broad_argument(nth_argument_or_keyword(&call.arguments, 0, "exception")?);
    }
    None
}

fn broad_argument(argument: &Expr) -> Option<&Expr> {
    let exception_type = match argument {
        Expr::Call(call) => call.func.as_ref(),
        type_expr => type_expr,
    };
    dotted_name(exception_type)
        .is_some_and(|path| BROAD_EXCEPTIONS.contains(&path.as_str()))
        .then_some(argument)
}
