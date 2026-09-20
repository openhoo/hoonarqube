use std::collections::HashSet;
use std::path::Path;

use ruff_python_ast::{
    ExceptHandler, Expr, ExprCall, FStringPart, InterpolatedStringElement, ModModule, Stmt,
    StmtFunctionDef,
};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

use crate::support::{
    child_bodies, dotted_name, for_each_stmt_expr_in_scope, for_each_stmt_in_scope,
    is_pytest_file_name, issue_at, nth_argument_or_keyword, single_assigned_constant, stmt_exprs,
    stmt_store_names,
};
use hoonarqube_ir::Issue;

const RULE_KEY: &str = "python:S8993";
const MESSAGE: &str = "Declare this fixture as a test function parameter instead of using \"request.getfixturevalue()\" with a string literal.";

/// python:S8993 — a collected pytest test function that resolves a fixture
/// through `request.getfixturevalue("name")` hides a dependency that the
/// signature could declare. The reference check requires the callee to be
/// `_pytest.fixtures.FixtureRequest.getfixturevalue`; pytest injects that
/// object only through the `request` parameter, so the lexical form is
/// `request.getfixturevalue(<arg>)` where `request` is a parameter of the
/// enclosing test function. The argument must be a static fixture name: a
/// plain string literal, an f-string without interpolations, or a name bound
/// exactly once to such a value (`Expressions.singleAssignedValue`). Dynamic
/// names (parametrized values, interpolated f-strings, `str.format`/`%`
/// results), calls inside `@pytest.fixture` functions, `pytest_*` hooks, and
/// `conftest.py` stay silent. The finding anchors the fixture-name argument.
pub(crate) fn check_s8993_fixture_param_dependencies(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
    path: &Path,
) -> Vec<Issue> {
    // `conftest.py` never satisfies the pytest file-name gate, so the
    // reference's conftest exemption is already covered.
    if !is_pytest_file_name(path) {
        return Vec::new();
    }
    let module = parsed.syntax().body.as_slice();
    let fixture_names = pytest_fixture_names(module);
    let mut issues = Vec::new();
    let mut pending: Vec<(&[Stmt], Option<&str>)> = vec![(module, None)];
    while let Some((stmts, enclosing_class)) = pending.pop() {
        for stmt in stmts {
            match stmt {
                Stmt::FunctionDef(function) => {
                    if is_collected_test(function, enclosing_class, &fixture_names) {
                        check_test_body(function, module, index, source, &mut issues);
                    }
                    pending.push((function.body.as_slice(), enclosing_class));
                }
                Stmt::ClassDef(class) => {
                    pending.push((class.body.as_slice(), Some(class.name.as_str())));
                }
                _ => {
                    for body in child_bodies(stmt) {
                        pending.push((body, enclosing_class));
                    }
                }
            }
        }
    }
    issues
}

/// Whether `function` is a collected pytest test: `test*` name, directly in a
/// `Test*` class or at module level, and not a `@pytest.fixture` function.
/// `pytest_*` hook names cannot satisfy the `test*` gate.
fn is_collected_test(
    function: &StmtFunctionDef,
    enclosing_class: Option<&str>,
    fixture_names: &HashSet<String>,
) -> bool {
    if !function.name.as_str().starts_with("test") {
        return false;
    }
    if enclosing_class.is_some_and(|name| !name.starts_with("Test")) {
        return false;
    }
    !is_pytest_fixture(function, fixture_names)
}

/// Whether any decorator resolves to `pytest.fixture`, bare or called,
/// including `from pytest import fixture [as x]` and `import pytest as x`
/// spellings.
fn is_pytest_fixture(function: &StmtFunctionDef, fixture_names: &HashSet<String>) -> bool {
    function.decorator_list.iter().any(|decorator| {
        let expression = match &decorator.expression {
            Expr::Call(call) => call.func.as_ref(),
            expression => expression,
        };
        dotted_name(expression).is_some_and(|name| fixture_names.contains(&name))
    })
}

/// Local spellings that denote `pytest.fixture` in this module.
fn pytest_fixture_names(module: &[Stmt]) -> HashSet<String> {
    let mut names = HashSet::from(["pytest.fixture".to_string()]);
    for stmt in module {
        match stmt {
            Stmt::Import(import) => collect_pytest_import(import, &mut names),
            Stmt::ImportFrom(import) => collect_pytest_from_import(import, &mut names),
            _ => {}
        }
    }
    names
}

/// `import pytest [as x]` contributes `<module>.fixture`.
fn collect_pytest_import(import: &ruff_python_ast::StmtImport, names: &mut HashSet<String>) {
    for alias in &import.names {
        if alias.name.as_str() == "pytest" {
            let module_name = alias.asname.as_ref().map_or("pytest", |n| n.as_str());
            names.insert(format!("{module_name}.fixture"));
        }
    }
}

/// `from pytest import fixture [as x]` contributes the local name.
fn collect_pytest_from_import(
    import: &ruff_python_ast::StmtImportFrom,
    names: &mut HashSet<String>,
) {
    if import.level != 0 || import.module.as_deref() != Some("pytest") {
        return;
    }
    for alias in &import.names {
        if alias.name.as_str() == "fixture" {
            names.insert(
                alias
                    .asname
                    .as_ref()
                    .map_or("fixture", |n| n.as_str())
                    .to_string(),
            );
        }
    }
}

/// Flags each `request.getfixturevalue(<static name>)` call in the test's own
/// scope; nested function and class bodies are separate scopes and are
/// reached by the outer walk instead.
fn check_test_body(
    function: &StmtFunctionDef,
    module: &[Stmt],
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    for_each_stmt_expr_in_scope(&function.body, &mut |expr| {
        let Expr::Call(call) = expr else {
            return;
        };
        let Some(fixture_name) = getfixturevalue_argument(call, function) else {
            return;
        };
        let mut visited = HashSet::new();
        if is_static_fixture_name(fixture_name, function, module, &mut visited) {
            issues.push(issue_at(
                RULE_KEY,
                MESSAGE,
                fixture_name.range(),
                index,
                source,
            ));
        }
    });
}

/// The fixture-name argument of `request.getfixturevalue(...)`: first
/// positional or `argname=` keyword, mirroring `nthArgumentOrKeyword(0,
/// "argname")`. The receiver must be the `request` parameter.
fn getfixturevalue_argument<'a>(
    call: &'a ExprCall,
    function: &StmtFunctionDef,
) -> Option<&'a Expr> {
    let Expr::Attribute(attribute) = call.func.as_ref() else {
        return None;
    };
    if attribute.attr.as_str() != "getfixturevalue" {
        return None;
    }
    let Expr::Name(receiver) = attribute.value.as_ref() else {
        return None;
    };
    if receiver.id.as_str() != "request" || !has_parameter(function, "request") {
        return None;
    }
    nth_argument_or_keyword(&call.arguments, 0, "argname")
}

/// Whether `name` is one of the function's parameters (positional, keyword,
/// `*args`, or `**kwargs`).
fn has_parameter(function: &StmtFunctionDef, name: &str) -> bool {
    let parameters = function.parameters.as_ref();
    parameters.find(name).is_some()
        || parameters
            .vararg
            .as_ref()
            .is_some_and(|p| p.name.as_str() == name)
        || parameters
            .kwarg
            .as_ref()
            .is_some_and(|p| p.name.as_str() == name)
}

/// `isStaticFixtureName`: a plain string literal, an f-string without
/// interpolations, or a name whose single assignment resolves to one.
fn is_static_fixture_name<'a>(
    expr: &'a Expr,
    function: &'a StmtFunctionDef,
    module: &'a [Stmt],
    visited: &mut HashSet<&'a str>,
) -> bool {
    match expr {
        Expr::Name(name) => {
            if !visited.insert(name.id.as_str()) {
                return false;
            }
            resolve_single_assignment(function, module, name.id.as_str())
                .is_some_and(|value| is_static_fixture_name(value, function, module, visited))
        }
        Expr::StringLiteral(_) => true,
        Expr::FString(fstring) => fstring.value.as_slice().iter().all(|part| match part {
            FStringPart::Literal(_) => true,
            FStringPart::FString(inner) => inner
                .elements
                .iter()
                .all(|element| matches!(element, InterpolatedStringElement::Literal(_))),
        }),
        _ => false,
    }
}

/// `Expressions.singleAssignedValue` restricted to the two scopes a test
/// function can see: its own body, then the module. `None` when the name is
/// bound by anything but one plain `name = value` / `name: T = value`
/// (parameters, multiple writes, imports, `for`/`with` targets, deletions).
fn resolve_single_assignment<'a>(
    function: &'a StmtFunctionDef,
    module: &'a [Stmt],
    name: &str,
) -> Option<&'a Expr> {
    if has_parameter(function, name) {
        return None;
    }
    if scope_binds(&function.body, name) {
        return single_assigned_constant(&function.body, name);
    }
    single_assigned_constant(module, name)
}

/// Whether the statement scope binds `name` anywhere (any store target,
/// walrus, `except ... as`, or match capture). `global`/`nonlocal`
/// declarations are not bindings; nested function/class bodies are skipped.
fn scope_binds(stmts: &[Stmt], name: &str) -> bool {
    let mut bound = false;
    for_each_stmt_in_scope(stmts, &mut |stmt| {
        bound = bound || stmt_binds(stmt, name);
    });
    bound
}

/// Whether one statement binds `name` in its own scope.
fn stmt_binds(stmt: &Stmt, name: &str) -> bool {
    match stmt {
        Stmt::Global(_) | Stmt::Nonlocal(_) => false,
        Stmt::Match(m) => m
            .cases
            .iter()
            .any(|case| pattern_binds(&case.pattern, name)),
        Stmt::Try(t) => t.handlers.iter().any(|handler| {
            let ExceptHandler::ExceptHandler(handler) = handler;
            handler.name.as_deref() == Some(name)
        }),
        _ => {
            stmt_store_names(stmt).iter().any(|n| n == name)
                || stmt_exprs(stmt).iter().any(|expr| expr_binds(expr, name))
        }
    }
}

/// Whether `expr` contains a `name := ...` walrus binding.
fn expr_binds(expr: &Expr, name: &str) -> bool {
    let mut found = false;
    crate::support::for_each_expr(expr, &mut |e| {
        if let Expr::Named(named) = e
            && matches!(named.target.as_ref(), Expr::Name(n) if n.id.as_str() == name)
        {
            found = true;
        }
    });
    found
}

/// Whether a match pattern captures `name` (`as`/`star`/mapping-rest names,
/// recursively through sequences, alternatives, and class patterns).
fn pattern_binds(pattern: &ruff_python_ast::Pattern, name: &str) -> bool {
    use ruff_python_ast::Pattern::{
        MatchAs, MatchClass, MatchMapping, MatchOr, MatchSequence, MatchSingleton, MatchStar,
        MatchValue,
    };
    match pattern {
        MatchAs(p) => {
            p.name.as_deref() == Some(name)
                || p.pattern
                    .as_deref()
                    .is_some_and(|inner| pattern_binds(inner, name))
        }
        MatchStar(p) => p.name.as_deref() == Some(name),
        MatchMapping(p) => {
            p.rest.as_deref() == Some(name)
                || p.patterns.iter().any(|inner| pattern_binds(inner, name))
        }
        MatchSequence(p) => p.patterns.iter().any(|inner| pattern_binds(inner, name)),
        MatchOr(p) => p.patterns.iter().any(|inner| pattern_binds(inner, name)),
        MatchClass(p) => {
            p.arguments
                .patterns
                .iter()
                .any(|inner| pattern_binds(inner, name))
                || p.arguments
                    .keywords
                    .iter()
                    .any(|keyword| pattern_binds(&keyword.pattern, name))
        }
        MatchValue(_) | MatchSingleton(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::test_support::{findings, pos, scan_at, scan_test_file};

    const KEY: &str = "python:S8993";

    #[test]
    fn s8993_flags_literal_and_keyword_fixture_names() {
        let report = scan_test_file(
            "import pytest\n\
             \n\
             @pytest.fixture\n\
             def database():\n\
             \x20   return object()\n\
             \n\
             def test_database_query(request):\n\
             \x20   db = request.getfixturevalue('database')\n\
             \x20   assert db is not None\n\
             \n\
             def test_keyword(request):\n\
             \x20   db = request.getfixturevalue(argname='database')\n\
             \x20   assert db is not None\n",
        );
        let hits = findings(&report, KEY);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].range.start, pos(8, 33));
        assert_eq!(hits[0].range.end, pos(8, 43));
        assert_eq!(hits[1].range.start, pos(12, 41));
    }

    #[test]
    fn s8993_flags_single_assigned_static_names() {
        let report = scan_test_file(
            "def test_dynamic_fixture_name(request):\n\
             \x20   name = 'database'\n\
             \x20   fixture = request.getfixturevalue(name)\n\
             \x20   assert fixture is not None\n",
        );
        let hits = findings(&report, KEY);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].range.start, pos(3, 38));
        assert_eq!(hits[0].range.end, pos(3, 42));
    }

    #[test]
    fn s8993_flags_useless_fstring_and_class_methods() {
        let report = scan_test_file(
            "def test_useless_fstring(request):\n\
             \x20   request.getfixturevalue(f\"database\")\n\
             \n\
             class TestClass:\n\
             \x20   def test_in_class(self, request):\n\
             \x20       request.getfixturevalue('database')\n",
        );
        let hits = findings(&report, KEY);
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].range.start, pos(2, 28));
        assert_eq!(hits[1].range.start, pos(6, 32));
    }

    #[test]
    fn s8993_accepts_fixtures_hooks_and_dynamic_names() {
        let report = scan_test_file(
            "import pytest\n\
             \n\
             @pytest.fixture(scope=\"module\")\n\
             def combined_with_scope(request):\n\
             \x20   return request.getfixturevalue('database')\n\
             \n\
             @pytest.fixture\n\
             def combined(request):\n\
             \x20   return request.getfixturevalue('database')\n\
             \n\
             def test_no_fixture_name_argument(request):\n\
             \x20   request.getfixturevalue()\n\
             \n\
             def test_other_fixture_request_method(request):\n\
             \x20   request.addfinalizer('cleanup')\n\
             \n\
             @pytest.mark.parametrize('fixture_name', ['database', 'cache'])\n\
             def test_matrix(request, fixture_name):\n\
             \x20   fixture = request.getfixturevalue(fixture_name)\n\
             \x20   assert fixture is not None\n\
             \n\
             def test_interpolated_fstring(request):\n\
             \x20   key = \"users\"\n\
             \x20   request.getfixturevalue(f\"pub_{key}\")\n\
             \x20   request.getfixturevalue(\"pub_{}\".format(key))\n\
             \x20   request.getfixturevalue(\"pub_%s\" % key)\n\
             \n\
             def helper_not_a_test(request):\n\
             \x20   request.getfixturevalue('database')\n",
        );
        assert!(findings(&report, KEY).is_empty());
    }

    #[test]
    fn s8993_flags_with_imported_fixture_decorator() {
        let report = scan_test_file(
            "from pytest import fixture\n\
             \n\
             @fixture\n\
             def combined(request):\n\
             \x20   return request.getfixturevalue('database')\n\
             \n\
             def pytest_runtest_setup(request):\n\
             \x20   request.getfixturevalue('database')\n\
             \n\
             def test_with_imported_fixture_decorator(request):\n\
             \x20   request.getfixturevalue('database')\n",
        );
        let hits = findings(&report, KEY);
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].range.start, pos(11, 28));
    }

    #[test]
    fn s8993_ignores_non_pytest_files_and_conftest() {
        let source = "def test_query(request):\n    request.getfixturevalue('database')\n";
        assert!(findings(&scan_at(PathBuf::from("helpers.py"), source), KEY).is_empty());
        assert!(findings(&scan_at(PathBuf::from("conftest.py"), source), KEY).is_empty());
    }
}
