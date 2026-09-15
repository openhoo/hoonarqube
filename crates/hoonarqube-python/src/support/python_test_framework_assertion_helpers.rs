// --- Shared helpers for the test-assertion detector family
//     (python:S3415, python:S5778, python:S5779, python:S5863,
//     python:S5958).
//
// The family mirrors Sonar's pytest/unittest gating: pytest-style checks
// require a pytest test file name plus a `test*` function (optionally in a
// `Test*` class), while unittest checks require the nearest enclosing class
// to subclass `TestCase`. Type-based decisions are approximated textually:
// dotted callee paths and base names decide, and unknown shapes stay silent.

use std::path::Path;

use ruff_python_ast::{
    Arguments, ExceptHandler, Expr, ExprCall, ExprDict, ExprList, ExprSet, ExprTuple, Stmt,
    StmtClassDef,
};
use ruff_source_file::LineIndex;
use ruff_text_size::TextRange;

use crate::support::child_exprs;
use crate::support::dotted_name;
use crate::support::keyword_value;
use crate::support::to_range;

/// Sonar's pytest file gate: the base name starts with `test_` or ends with
/// `_test.py`.
pub(crate) fn is_pytest_file_name(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    name.starts_with("test_") || name.ends_with("_test.py")
}

/// Sonar's Main/TEST scope boundary for rules whose catalog scope is MAIN:
/// a file is test-scoped when a path component is a conventional test
/// directory (`test`, `tests`, `testing`) or the file name follows the
/// pytest/`conftest` conventions. MAIN-scope rules never report on such
/// files, mirroring the reference platform's issue filtering.
pub(crate) fn is_test_scope_file(path: &Path) -> bool {
    let in_test_directory = path.components().any(|component| {
        matches!(
            component.as_os_str().to_str(),
            Some("test" | "tests" | "testing")
        )
    });
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return in_test_directory;
    };
    in_test_directory
        || name.starts_with("test")
        || name.starts_with("conftest")
        || name.ends_with("_test.py")
}

/// Nearest-ancestor context shared by the family's walkers.
#[derive(Clone, Copy)]
pub(crate) struct TestScope<'a> {
    /// Name of the nearest enclosing function, if any.
    pub(crate) function: Option<&'a str>,
    /// Name of the class directly enclosing that function, if any.
    pub(crate) function_class: Option<&'a str>,
    /// Name of the nearest enclosing class, if any.
    pub(crate) class: Option<&'a str>,
    /// Whether the nearest enclosing class subclasses `TestCase`.
    pub(crate) class_is_testcase: bool,
}

impl<'a> TestScope<'a> {
    pub(crate) fn root() -> Self {
        Self {
            function: None,
            function_class: None,
            class: None,
            class_is_testcase: false,
        }
    }

    /// Whether the current function is a pytest-style test: pytest file
    /// name, `test*` function, and no direct class or a `Test*` class.
    pub(crate) fn is_pytest_style_function(&self, pytest_file: bool) -> bool {
        pytest_file
            && self.function.is_some_and(|name| name.starts_with("test"))
            && self
                .function_class
                .is_none_or(|name| name.starts_with("Test"))
    }

    /// Context inside one function body: the function and its direct class.
    pub(crate) fn enter_function(self, name: &'a str) -> Self {
        Self {
            function: Some(name),
            function_class: self.class,
            ..self
        }
    }

    /// Context inside one class body.
    pub(crate) fn enter_class(name: &'a str, testcase: bool) -> Self {
        Self {
            function: None,
            function_class: None,
            class: Some(name),
            class_is_testcase: testcase,
        }
    }
}

/// Whether `class_def` declares a `TestCase` base (textually: any base whose
/// dotted path is `TestCase` or ends with `.TestCase`).
pub(crate) fn class_is_testcase_subclass(class_def: &StmtClassDef) -> bool {
    let Some(arguments) = class_def.arguments.as_deref() else {
        return false;
    };
    arguments.args.iter().any(|base| {
        dotted_name(base).is_some_and(|path| path == "TestCase" || path.ends_with(".TestCase"))
    })
}

/// Whether `call` invokes `self.<method>` (textual self receiver), returning
/// the method name.
pub(crate) fn self_method_name<'a>(call: &'a ExprCall, methods: &[&str]) -> Option<&'a str> {
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return None;
    };
    let Expr::Name(receiver) = attribute.value.as_ref() else {
        return None;
    };
    let is_self = receiver.id.as_str() == "self" && methods.contains(&attribute.attr.as_str());
    is_self.then_some(attribute.attr.as_str())
}

/// First positional argument or the `keyword`-named argument.
pub(crate) fn nth_argument_or_keyword<'a>(
    arguments: &'a Arguments,
    index: usize,
    keyword: &str,
) -> Option<&'a Expr> {
    arguments
        .args
        .get(index)
        .filter(|argument| !argument.is_starred_expr())
        .or_else(|| keyword_value(arguments, keyword))
}

/// `CheckUtils.isImmutableConstant`: booleans, numbers, strings, bytes,
/// `None`, lambdas, and generator expressions.
pub(crate) fn is_immutable_constant(expr: &Expr) -> bool {
    matches!(
        expr,
        Expr::BooleanLiteral(_)
            | Expr::NumberLiteral(_)
            | Expr::StringLiteral(_)
            | Expr::BytesLiteral(_)
            | Expr::NoneLiteral(_)
            | Expr::Lambda(_)
            | Expr::Generator(_)
    )
}

/// Whether a collection literal contains starred elements or dict unpacking.
fn has_unpacking(expr: &Expr) -> bool {
    match expr {
        Expr::List(ExprList { elts, .. })
        | Expr::Set(ExprSet { elts, .. })
        | Expr::Tuple(ExprTuple { elts, .. }) => elts.iter().any(Expr::is_starred_expr),
        Expr::Dict(ExprDict { items, .. }) => items.iter().any(|item| item.key.is_none()),
        _ => false,
    }
}

/// `CheckUtils.isConstant`: immutable constants plus collection literals
/// without unpacking (element values are not inspected, as upstream).
pub(crate) fn is_assertion_constant(expr: &Expr) -> bool {
    let collection = matches!(
        expr,
        Expr::List(_) | Expr::Tuple(_) | Expr::Set(_) | Expr::Dict(_)
    );
    is_immutable_constant(expr) || (collection && !has_unpacking(expr))
}

/// Sonar's expected-value classifier for assertion arguments: constants,
/// `pytest.approx(<constant>)`, and names bound exactly once to an immutable
/// constant within the enclosing scope.
pub(crate) fn is_expected_value(expr: &Expr, scope: &[Stmt]) -> bool {
    match expr {
        Expr::Name(name) => {
            single_assigned_constant(scope, name.id.as_str()).is_some_and(is_immutable_constant)
        }
        Expr::Call(call) if dotted_name(&call.func).as_deref() == Some("pytest.approx") => call
            .arguments
            .args
            .first()
            .is_some_and(|argument| is_expected_value(argument, scope)),
        _ => is_assertion_constant(expr),
    }
}

// ---------------------------------------------------------------------------
// Single-write literal facts for expected-value names.
//
// Mirrors Sonar's `singleAssignedNonNameValue(name).filter(isImmutableConstant)`
// within one scope: the name must be bound exactly once, by a plain literal
// assignment. Rebinding, augmented assignments, loop/with/walrus/import/
// global/match bindings, and deletions disqualify the name. Nested function
// and class bodies are separate scopes.
// ---------------------------------------------------------------------------

/// The single-write resolution for one name within a scope.
enum SingleWrite<'a> {
    /// No write seen yet; the assigned literal, if the only write.
    Pending(Option<&'a Expr>),
    /// More than one write (or an unresolvable write shape).
    Many,
}

/// The literal value assigned to `name` by the scope's only write, if that
/// write is a plain assignment of a literal expression.
pub(crate) fn single_assigned_constant<'a>(stmts: &'a [Stmt], name: &str) -> Option<&'a Expr> {
    let mut resolution = SingleWrite::Pending(None);
    collect_scope_writes(stmts, name, &mut resolution);
    match resolution {
        SingleWrite::Pending(value) => value,
        SingleWrite::Many => None,
    }
}

fn collect_scope_writes<'a>(stmts: &'a [Stmt], name: &str, resolution: &mut SingleWrite<'a>) {
    for stmt in stmts {
        if matches!(resolution, SingleWrite::Many) {
            return;
        }
        match stmt {
            Stmt::Assign(assign) => {
                record_plain_assign(assign.targets.as_slice(), &assign.value, name, resolution);
            }
            Stmt::AnnAssign(ann) => {
                let value = ann.value.as_deref();
                record_annotated_assign(ann.target.as_ref(), value, name, resolution);
            }
            Stmt::AugAssign(aug) if is_bare_target(aug.target.as_ref(), name) => {
                *resolution = SingleWrite::Many;
            }
            Stmt::For(f) => {
                disqualify_if_binds(f.target.as_ref(), name, resolution);
                collect_scope_writes(f.body.as_slice(), name, resolution);
                collect_scope_writes(f.orelse.as_slice(), name, resolution);
            }
            Stmt::With(w) => {
                disqualify_with_bindings(w, name, resolution);
                collect_scope_writes(w.body.as_slice(), name, resolution);
            }
            Stmt::Try(t) => {
                collect_scope_writes(t.body.as_slice(), name, resolution);
                for handler in &t.handlers {
                    let ExceptHandler::ExceptHandler(inner) = handler;
                    collect_scope_writes(inner.body.as_slice(), name, resolution);
                }
                collect_scope_writes(t.orelse.as_slice(), name, resolution);
                collect_scope_writes(t.finalbody.as_slice(), name, resolution);
            }
            Stmt::If(i) => {
                collect_scope_writes(i.body.as_slice(), name, resolution);
                for clause in &i.elif_else_clauses {
                    collect_scope_writes(clause.body.as_slice(), name, resolution);
                }
            }
            Stmt::While(w) => {
                collect_scope_writes(w.body.as_slice(), name, resolution);
                collect_scope_writes(w.orelse.as_slice(), name, resolution);
            }
            Stmt::Match(m) => {
                disqualify_if_binds(m.subject.as_ref(), name, resolution);
                for case in &m.cases {
                    disqualify_pattern_captures(&case.pattern, name, resolution);
                    collect_scope_writes(case.body.as_slice(), name, resolution);
                }
            }
            Stmt::FunctionDef(_) | Stmt::ClassDef(_) => {}
            other => scan_walrus_writes(other, name, resolution),
        }
    }
}

/// Records a plain `Assign`: exactly one bare `name` target keeps the literal
/// value; tuple/chained/multiple targets disqualify.
fn record_plain_assign<'a>(
    targets: &'a [Expr],
    value: &'a Expr,
    name: &str,
    resolution: &mut SingleWrite<'a>,
) {
    let binding = targets
        .iter()
        .find(|target| expr_binds_target(target, name));
    if let Some(Expr::Name(_)) = binding
        && targets.len() == 1
    {
        record_literal(value, resolution);
        return;
    }
    if binding.is_some() {
        *resolution = SingleWrite::Many;
    }
}

/// Records an `AnnAssign`: a bare `name` target with a value keeps the
/// literal; a bare annotation without value disqualifies.
fn record_annotated_assign<'a>(
    target: &'a Expr,
    value: Option<&'a Expr>,
    name: &str,
    resolution: &mut SingleWrite<'a>,
) {
    if !is_bare_target(target, name) {
        return;
    }
    match value {
        Some(value) => record_literal(value, resolution),
        None => *resolution = SingleWrite::Many,
    }
}

fn record_literal<'a>(value: &'a Expr, resolution: &mut SingleWrite<'a>) {
    match resolution {
        SingleWrite::Pending(slot) => {
            if slot.is_some() {
                // A second binding destroys the single-assignment fact.
                *resolution = SingleWrite::Many;
            } else {
                *slot = Some(value);
            }
        }
        SingleWrite::Many => {}
    }
}

/// Whether `target` is exactly the name being tracked.
fn is_bare_target(target: &Expr, name: &str) -> bool {
    matches!(target, Expr::Name(bound) if bound.id.as_str() == name)
}

/// Whether `target` binds the tracked name (barely, or inside a tuple/list
/// unpacking pattern). Attribute and subscript targets mutate instead of
/// rebinding and never bind.
fn expr_binds_target(target: &Expr, name: &str) -> bool {
    match target {
        Expr::Name(bound) => bound.id.as_str() == name,
        Expr::Tuple(ExprTuple { elts, .. }) | Expr::List(ExprList { elts, .. }) => {
            elts.iter().any(|element| expr_binds_target(element, name))
        }
        Expr::Starred(starred) => expr_binds_target(starred.value.as_ref(), name),
        _ => false,
    }
}

fn disqualify_if_binds<'a>(target: &'a Expr, name: &str, resolution: &mut SingleWrite<'a>) {
    if expr_binds_target(target, name) {
        *resolution = SingleWrite::Many;
    }
}

fn disqualify_with_bindings<'a>(
    with: &'a ruff_python_ast::StmtWith,
    name: &str,
    resolution: &mut SingleWrite<'a>,
) {
    for item in &with.items {
        if let Some(vars) = item.optional_vars.as_deref() {
            disqualify_if_binds(vars, name, resolution);
        }
    }
}

fn disqualify_pattern_captures(
    pattern: &ruff_python_ast::Pattern,
    name: &str,
    resolution: &mut SingleWrite,
) {
    let captures = pattern_capture_names(pattern);
    if captures.iter().any(|captured| captured == name) {
        *resolution = SingleWrite::Many;
    }
}
fn collect_pattern_captures(pattern: &ruff_python_ast::Pattern, names: &mut Vec<String>) {
    match pattern {
        ruff_python_ast::Pattern::MatchValue(_) | ruff_python_ast::Pattern::MatchSingleton(_) => {}
        ruff_python_ast::Pattern::MatchSequence(sequence) => {
            collect_subpattern_captures(&sequence.patterns, names);
        }
        ruff_python_ast::Pattern::MatchOr(match_or) => {
            collect_subpattern_captures(&match_or.patterns, names);
        }
        ruff_python_ast::Pattern::MatchMapping(mapping) => {
            collect_subpattern_captures(&mapping.patterns, names);
            if let Some(rest) = &mapping.rest {
                names.push(rest.as_str().to_string());
            }
        }
        ruff_python_ast::Pattern::MatchClass(class) => {
            collect_subpattern_captures(&class.arguments.patterns, names);
            for keyword in &class.arguments.keywords {
                collect_pattern_captures(&keyword.pattern, names);
            }
        }
        ruff_python_ast::Pattern::MatchStar(star) => {
            if let Some(rest) = &star.name {
                names.push(rest.as_str().to_string());
            }
        }
        ruff_python_ast::Pattern::MatchAs(match_as) => {
            if let Some(subpattern) = match_as.pattern.as_deref() {
                collect_pattern_captures(subpattern, names);
            }
            if let Some(rest) = &match_as.name {
                names.push(rest.as_str().to_string());
            }
        }
    }
}
/// Flat capture names of a match pattern (`MatchAs`, `MatchStar`,
/// `MatchMapping` rest).
fn pattern_capture_names(pattern: &ruff_python_ast::Pattern) -> Vec<String> {
    let mut names = Vec::new();
    collect_pattern_captures(pattern, &mut names);
    names
}

fn collect_subpattern_captures(patterns: &[ruff_python_ast::Pattern], names: &mut Vec<String>) {
    for subpattern in patterns {
        collect_pattern_captures(subpattern, names);
    }
}

/// Scans the statements' own expressions for walrus writes to `name`.
fn scan_walrus_writes(stmt: &Stmt, name: &str, resolution: &mut SingleWrite) {
    for expr in crate::support::stmt_exprs(stmt) {
        scan_walrus_expr(expr, name, resolution);
    }
}

fn scan_walrus_expr(expr: &Expr, name: &str, resolution: &mut SingleWrite) {
    let mut pending = vec![expr];
    while let Some(current) = pending.pop() {
        if let Expr::Named(named) = current
            && is_bare_target(named.target.as_ref(), name)
        {
            *resolution = SingleWrite::Many;
            return;
        }
        pending.extend(child_exprs(current));
    }
}

/// One flow location in the analyzed file.
pub(crate) fn flow_location(
    message: &str,
    range: TextRange,
    index: &LineIndex,
    source: &str,
) -> hoonarqube_ir::FlowLocation {
    hoonarqube_ir::FlowLocation::in_primary_file(message, to_range(range, index, source))
}
