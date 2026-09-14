use hoonarqube_ir::Issue;
use ruff_python_ast::token::{TokenKind, Tokens};
use ruff_python_ast::{Expr, ExprCall, ModModule, Stmt, StmtWith, WithItem};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use crate::support::TestScope;
use crate::support::child_bodies;
use crate::support::child_exprs;
use crate::support::class_is_testcase_subclass;
use crate::support::dotted_name;
use crate::support::flow_location;
use crate::support::issue_at;
use crate::support::self_method_name;
use crate::support::stmt_exprs;

const RULE_KEY: &str = "python:S5778";
const MESSAGE: &str =
    "Refactor this exception test to have only one invocation possibly throwing an exception.";
const INVOCATION_FLOW: &str = "Invocation possibly throwing an exception.";

/// unittest methods that assert raised exceptions.
const RAISE_METHODS: [&str; 3] = ["assertRaises", "assertRaisesRegex", "assertRaisesRegexp"];

/// Bare callees that are almost never the exception under test (Sonar's
/// always-safe list, matched textually; `Path`/`UUID` cover the common
/// unprefixed imports of the dotted utilities below).
const ALWAYS_SAFE_BARE: [&str; 34] = [
    "str",
    "bytes",
    "bytearray",
    "repr",
    "ascii",
    "format",
    "bool",
    "int",
    "float",
    "complex",
    "memoryview",
    "list",
    "tuple",
    "dict",
    "print",
    "len",
    "abs",
    "round",
    "id",
    "hash",
    "hex",
    "oct",
    "bin",
    "ord",
    "chr",
    "range",
    "enumerate",
    "zip",
    "reversed",
    "sorted",
    "slice",
    "callable",
    "Path",
    "UUID",
];
/// Dotted callees that are always safe.
const ALWAYS_SAFE_DOTTED: [&str; 15] = [
    "pathlib.Path",
    "pathlib.PurePath",
    "pathlib.PosixPath",
    "pathlib.WindowsPath",
    "pathlib.PurePosixPath",
    "pathlib.PureWindowsPath",
    "uuid.UUID",
    "uuid.uuid1",
    "uuid.uuid3",
    "uuid.uuid4",
    "uuid.uuid5",
    "uuid.uuid6",
    "uuid.uuid7",
    "copy.copy",
    "copy.deepcopy",
];
/// Constructors that are safe only without arguments.
const EMPTY_ARGS_SAFE: [&str; 3] = ["set", "frozenset", "object"];

/// python:S5778 — only one method invocation is expected when testing
/// runtime exceptions. A `pytest.raises(...)` or unittest `assertRaises(...)`
/// block, or a raises call with a lambda argument, whose body can invoke more
/// than one throwing call makes the exception source ambiguous.
pub(crate) fn check_s5778_single_invocation_runtime_exception(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    walk_s5778(
        parsed.syntax().body.as_slice(),
        &TestScope::root(),
        parsed.tokens(),
        index,
        source,
        &mut issues,
    );
    issues
}

fn walk_s5778<'a>(
    stmts: &'a [Stmt],
    scope: &TestScope<'a>,
    tokens: &Tokens,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(function) => {
                let inner = scope.enter_function(function.name.as_str());
                walk_s5778(
                    function.body.as_slice(),
                    &inner,
                    tokens,
                    index,
                    source,
                    issues,
                );
            }
            Stmt::ClassDef(class) => {
                let inner =
                    TestScope::enter_class(class.name.as_str(), class_is_testcase_subclass(class));
                walk_s5778(class.body.as_slice(), &inner, tokens, index, source, issues);
            }
            Stmt::With(with_stmt) => {
                check_raises_block(with_stmt, scope, tokens, index, source, issues);
                for item in &with_stmt.items {
                    check_lambda_form(&item.context_expr, scope, index, source, issues);
                }
                walk_s5778(
                    with_stmt.body.as_slice(),
                    scope,
                    tokens,
                    index,
                    source,
                    issues,
                );
            }
            other => {
                for expr in stmt_exprs(other) {
                    check_lambda_form(expr, scope, index, source, issues);
                }
                for body in child_bodies(other) {
                    walk_s5778(body, scope, tokens, index, source, issues);
                }
            }
        }
    }
}

/// Flags a raises block whose body holds more than one unsafe invocation.
fn check_raises_block(
    with_stmt: &StmtWith,
    scope: &TestScope,
    tokens: &Tokens,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let raises = with_stmt
        .items
        .iter()
        .any(|item| matches!(&item.context_expr, Expr::Call(call) if is_raises_call(call, scope)));
    if !raises {
        return;
    }
    let invocations = unsafe_invocations_in_stmts(with_stmt.body.as_slice());
    if invocations.len() <= 1 {
        return;
    }
    let mut issue = issue_at(
        RULE_KEY,
        MESSAGE,
        with_header_range(with_stmt, tokens),
        index,
        source,
    );
    issue.flows.push(hoonarqube_ir::IssueFlow {
        locations: invocations
            .iter()
            .map(|call| flow_location(INVOCATION_FLOW, invocation_range(call), index, source))
            .collect(),
    });
    issues.push(issue);
}

/// Flags `pytest.raises(E, lambda: ...)` bodies with several unsafe calls.
fn check_lambda_form(
    expr: &Expr,
    scope: &TestScope,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let Expr::Call(call) = expr else {
        return;
    };
    if !is_raises_call(call, scope) {
        return;
    }
    let Some(lambda) = call
        .arguments
        .args
        .iter()
        .find_map(|argument| argument.as_lambda_expr())
    else {
        return;
    };
    let mut invocations = Vec::new();
    collect_unsafe_calls(lambda.body.as_ref(), &mut invocations);
    if invocations.len() <= 1 {
        return;
    }
    let mut issue = issue_at(RULE_KEY, MESSAGE, call.range(), index, source);
    issue.flows.push(hoonarqube_ir::IssueFlow {
        locations: invocations
            .iter()
            .map(|inner| flow_location(INVOCATION_FLOW, invocation_range(inner), index, source))
            .collect(),
    });
    issues.push(issue);
}

/// Whether `call` asserts a raised exception.
fn is_raises_call(call: &ExprCall, scope: &TestScope) -> bool {
    dotted_name(&call.func).as_deref() == Some("pytest.raises")
        || (scope.class_is_testcase && self_method_name(call, &RAISE_METHODS).is_some())
}

/// Calls in the statements that can throw, sorted by position. Safe setup
/// helpers never count; lambda and nested-definition bodies do not execute
/// with the block.
fn unsafe_invocations_in_stmts(stmts: &[Stmt]) -> Vec<&ExprCall> {
    let mut invocations = Vec::new();
    collect_stmt_invocations(stmts, &mut invocations);
    invocations.sort_by_key(|call| call.range().start());
    invocations
}

fn collect_stmt_invocations<'a>(stmts: &'a [Stmt], out: &mut Vec<&'a ExprCall>) {
    for stmt in stmts {
        match stmt {
            Stmt::FunctionDef(_) | Stmt::ClassDef(_) => {}
            other => {
                for expr in stmt_exprs(other) {
                    collect_unsafe_calls(expr, out);
                }
                for body in child_bodies(other) {
                    collect_stmt_invocations(body, out);
                }
            }
        }
    }
}

fn collect_unsafe_calls<'a>(expr: &'a Expr, out: &mut Vec<&'a ExprCall>) {
    // Nested lambdas define deferred execution and do not contribute.
    if matches!(expr, Expr::Lambda(_)) {
        return;
    }
    if let Expr::Call(call) = expr
        && !is_safe_call(call)
    {
        out.push(call);
    }
    for child in child_exprs(expr) {
        collect_unsafe_calls(child, out);
    }
}

/// Textual approximation of Sonar's safe-call lists: bare builtins, exact
/// dotted utilities, NumPy/SciPy prefixes, and empty safe constructors.
fn is_safe_call(call: &ExprCall) -> bool {
    let Some(path) = dotted_name(&call.func) else {
        return false;
    };
    let path = path.as_str();
    let bare_safe = ALWAYS_SAFE_BARE.contains(&path) && matches!(call.func.as_ref(), Expr::Name(_));
    let dotted_safe = ALWAYS_SAFE_DOTTED.contains(&path)
        || path.starts_with("numpy.")
        || path.starts_with("scipy.");
    let empty_safe = EMPTY_ARGS_SAFE.contains(&path)
        && call.arguments.args.is_empty()
        && call.arguments.keywords.is_empty();
    bare_safe || dotted_safe || empty_safe
}

/// Sonar anchors the finding from the `with` keyword to the header colon.
fn with_header_range(with_stmt: &StmtWith, tokens: &Tokens) -> TextRange {
    let start = with_stmt.range().start();
    let items_end = with_stmt
        .items
        .last()
        .map_or(start, |item: &WithItem| item.range().end());
    let body_start = with_stmt
        .body
        .first()
        .map_or(items_end, |first| first.range().start());
    let colon = tokens
        .iter()
        .filter(|token| token.kind() == TokenKind::Colon)
        .map(Ranged::range)
        .find(|range| range.start() >= items_end && range.end() <= body_start);
    TextRange::new(start, colon.map_or(items_end, TextRange::end))
}

/// Sonar locates an invocation from its callee name to the closing paren.
fn invocation_range(call: &ExprCall) -> TextRange {
    let start = match call.func.as_ref() {
        Expr::Attribute(attribute) => attribute.attr.range().start(),
        Expr::Name(name) => name.range().start(),
        _ => call.range().start(),
    };
    TextRange::new(start, call.arguments.range().end())
}
