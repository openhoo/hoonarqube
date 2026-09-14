use hoonarqube_ir::Issue;
use ruff_python_ast::{
    ExceptHandler, ExceptHandlerExceptHandler, Expr, ModModule, Stmt, StmtExpr, StmtTry,
};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange, TextSize};

use crate::support::TestScope;
use crate::support::child_bodies;
use crate::support::class_is_testcase_subclass;
use crate::support::dotted_name;
use crate::support::flow_location;
use crate::support::issue_at;
use crate::support::self_method_name;

const RULE_KEY: &str = "python:S5779";
const ASSERT_MESSAGE: &str = "Don't use assert inside a try-except that catches AssertionError.";
const CALL_MESSAGE_TEMPLATE: &str =
    "Don't use {method} inside a try-except that catches AssertionError.";
const ASSERTION_ERROR_FLOW: &str = "AssertionError is caught here.";
const EXCEPTION_FLOW: &str = "Exception is caught here.";
const BASE_EXCEPTION_FLOW: &str = "BaseException is caught here.";
const BARE_FLOW: &str = "All exceptions are caught here.";

/// Exception types that catch `AssertionError`, matched textually.
const ASSERTION_CATCHERS: [&str; 5] = [
    "AssertionError",
    "Exception",
    "BaseException",
    "builtins.Exception",
    "builtins.BaseException",
];

/// unittest assertion methods, matched as `self.<method>(...)` statements.
const UNITTEST_ASSERT_METHODS: [&str; 38] = [
    "assertEqual",
    "assertNotEqual",
    "assertTrue",
    "assertFalse",
    "assertIs",
    "assertIsNot",
    "assertIsNone",
    "assertIsNotNone",
    "assertIn",
    "assertNotIn",
    "assertIsInstance",
    "assertNotIsInstance",
    "assertAlmostEqual",
    "assertNotAlmostEqual",
    "assertGreater",
    "assertGreaterEqual",
    "assertLess",
    "assertLessEqual",
    "assertRegexpMatches",
    "assertNotRegexpMatches",
    "assertItemsEqual",
    "assertDictContainsSubset",
    "assertMultiLineEqual",
    "assertSequenceEqual",
    "assertListEqual",
    "assertTupleEqual",
    "assertSetEqual",
    "assertDictEqual",
    "assertWarns",
    "assertWarnsRegex",
    "assertLogs",
    "assertNoLogs",
    "assertRegex",
    "assertNotRegex",
    "assertCountEqual",
    "assertRaises",
    "assertRaisesRegex",
    "assertRaisesRegexp",
];

/// One enclosing `try` whose body may swallow assertion failures.
struct TryGuard {
    swallows_assertion: bool,
    reraises: bool,
    flow: Option<(&'static str, TextRange)>,
}

/// python:S5779 — assertions should not be made within the try block of a
/// try-except catching `AssertionError` (or `Exception`/`BaseException`, or bare
/// handlers) without re-raising: the handler swallows the failure.
pub(crate) fn check_s5779_assertion_in_try(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_s5779(
        parsed.syntax().body.as_slice(),
        &mut Vec::new(),
        &TestScope::root(),
        index,
        source,
        &mut issues,
    );
    issues
}

fn walk_s5779<'a>(
    stmts: &'a [Stmt],
    guards: &mut Vec<TryGuard>,
    scope: &TestScope<'a>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(function) => {
                let inner = scope.enter_function(function.name.as_str());
                walk_s5779(
                    function.body.as_slice(),
                    guards,
                    &inner,
                    index,
                    source,
                    issues,
                );
            }
            Stmt::ClassDef(class) => {
                let inner =
                    TestScope::enter_class(class.name.as_str(), class_is_testcase_subclass(class));
                walk_s5779(class.body.as_slice(), guards, &inner, index, source, issues);
            }
            Stmt::Try(try_stmt) => {
                walk_try(try_stmt, guards, scope, index, source, issues);
            }
            Stmt::Assert(assert) => {
                if let Some(issue) =
                    guarded_issue(guards, ASSERT_MESSAGE, assert.range(), index, source)
                {
                    issues.push(issue);
                }
            }
            Stmt::Expr(statement) => {
                check_unittest_assertion(statement, guards, scope, index, source, issues);
            }
            other => {
                for body in child_bodies(other) {
                    walk_s5779(body, guards, scope, index, source, issues);
                }
            }
        }
    }
}

/// Walks one try statement: the body inherits its handlers as guards, while
/// handler, `else`, and `finally` suites do not.
fn walk_try<'a>(
    try_stmt: &'a StmtTry,
    guards: &mut Vec<TryGuard>,
    scope: &TestScope<'a>,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let depth = guards.len();
    let starred = try_stmt.is_star;
    for handler in &try_stmt.handlers {
        let ExceptHandler::ExceptHandler(inner) = handler;
        let flow = if starred { None } else { catch_flow(inner) };
        guards.push(TryGuard {
            swallows_assertion: flow.is_some(),
            reraises: handler_reraises(inner),
            flow,
        });
    }
    walk_s5779(
        try_stmt.body.as_slice(),
        guards,
        scope,
        index,
        source,
        issues,
    );
    guards.truncate(depth);
    for handler in &try_stmt.handlers {
        let ExceptHandler::ExceptHandler(inner) = handler;
        walk_s5779(inner.body.as_slice(), guards, scope, index, source, issues);
    }
    walk_s5779(
        try_stmt.orelse.as_slice(),
        guards,
        scope,
        index,
        source,
        issues,
    );
    walk_s5779(
        try_stmt.finalbody.as_slice(),
        guards,
        scope,
        index,
        source,
        issues,
    );
}

/// The innermost guard that swallows assertion failures.
fn swallowing_guard(guards: &[TryGuard]) -> Option<&TryGuard> {
    guards
        .iter()
        .rev()
        .find(|guard| guard.swallows_assertion && !guard.reraises)
}

/// The finding for one guarded assertion, when a swallowing guard encloses it.
fn guarded_issue(
    guards: &[TryGuard],
    message: &str,
    range: TextRange,
    index: &LineIndex,
    source: &str,
) -> Option<Issue> {
    let guard = swallowing_guard(guards)?;
    let (flow_message, flow_range) = guard.flow?;
    let mut issue = issue_at(RULE_KEY, message, range, index, source);
    issue.flows.push(hoonarqube_ir::IssueFlow {
        locations: vec![flow_location(flow_message, flow_range, index, source)],
    });
    Some(issue)
}

/// Flags `self.assertX(...)` expression statements under a swallowing guard.
fn check_unittest_assertion(
    statement: &StmtExpr,
    guards: &[TryGuard],
    scope: &TestScope,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let Expr::Call(call) = statement.value.as_ref() else {
        return;
    };
    let Some(method) = self_method_name(call, &UNITTEST_ASSERT_METHODS) else {
        return;
    };
    if !scope.class_is_testcase {
        return;
    }
    let message = CALL_MESSAGE_TEMPLATE.replace("{method}", method);
    if let Some(issue) = guarded_issue(guards, &message, call.range(), index, source) {
        issues.push(issue);
    }
}

/// Whether a handler catches (or subsumes) `AssertionError`, plus its flow.
fn catch_flow(handler: &ExceptHandlerExceptHandler) -> Option<(&'static str, TextRange)> {
    let Some(exception) = handler.type_.as_deref() else {
        return Some((
            BARE_FLOW,
            TextRange::at(handler.range().start(), TextSize::new(6)),
        ));
    };
    let caught = flattened_exceptions(exception)
        .into_iter()
        .find(|path| ASSERTION_CATCHERS.contains(&path.as_str()))?;
    let message = match caught.as_str() {
        "Exception" | "builtins.Exception" => EXCEPTION_FLOW,
        "BaseException" | "builtins.BaseException" => BASE_EXCEPTION_FLOW,
        _ => ASSERTION_ERROR_FLOW,
    };
    Some((message, exception.range()))
}

/// Dotted paths of a caught exception expression, flattening tuples.
fn flattened_exceptions(exception: &Expr) -> Vec<String> {
    match exception {
        Expr::Tuple(tuple) => tuple.elts.iter().flat_map(flattened_exceptions).collect(),
        other => dotted_name(other).into_iter().collect(),
    }
}

/// Whether the handler re-raises (bare `raise` or the bound alias).
fn handler_reraises(handler: &ExceptHandlerExceptHandler) -> bool {
    let alias = handler
        .name
        .as_ref()
        .map(ruff_python_ast::Identifier::as_str);
    handler.body.iter().any(|stmt| match stmt {
        Stmt::Raise(raise) => match raise.exc.as_deref() {
            None => true,
            Some(Expr::Name(reraised)) => alias == Some(reraised.id.as_str()),
            Some(_) => false,
        },
        _ => false,
    })
}
