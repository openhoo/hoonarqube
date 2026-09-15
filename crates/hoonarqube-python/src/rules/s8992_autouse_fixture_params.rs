use ruff_python_ast::{Expr, ModModule, Stmt};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::{Ranged, TextRange};

use hoonarqube_ir::Issue;

use crate::support::dotted_name_is;
use crate::support::for_each_stmt;
use crate::support::issue_at;

const RULE_KEY: &str = "python:S8992";
const MESSAGE: &str = "Remove the \"params\" argument or set \"autouse\" to False.";

/// python:S8992 — a `@pytest.fixture` decorator combining `autouse=True`
/// with a `params` argument carrying values implicitly parametrizes every
/// test in its scope, including tests that never request the fixture, so
/// the test multiplication is invisible at the test site. The decorator
/// combination alone keys the rule and, unlike the file-gated pytest
/// family, it also fires in helpers and `conftest.py` (catalog scope
/// ALL). The decorator anchors the finding. `params=None` and empty
/// literal collections carry no values, `autouse=False` opts out, and
/// decorators outside `pytest.fixture` stay silent.
pub(crate) fn check_s8992_autouse_fixture_params(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt(parsed.syntax().body.as_slice(), &mut |stmt| {
        let Stmt::FunctionDef(function) = stmt else {
            return;
        };
        for decorator in &function.decorator_list {
            check_fixture_decorator(
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

/// The `autouse=True` plus populated `params` combination of one
/// `pytest.fixture` call decorator. `range` spans the whole decorator
/// syntax including the leading `@`, matching Sonar's decorator anchor.
fn check_fixture_decorator(
    expression: &Expr,
    range: TextRange,
    index: &LineIndex,
    source: &str,
    issues: &mut Vec<Issue>,
) {
    let Expr::Call(call) = expression else {
        return;
    };
    if !dotted_name_is(&call.func, "pytest.fixture") {
        return;
    }
    let keywords = &call.arguments.keywords;
    let autouse_active = keywords.iter().any(|keyword| {
        keyword
            .arg
            .as_ref()
            .is_some_and(|arg| arg.as_str() == "autouse")
            && is_boolean_true(&keyword.value)
    });
    let params_with_values = keywords.iter().any(|keyword| {
        keyword
            .arg
            .as_ref()
            .is_some_and(|arg| arg.as_str() == "params")
            && carries_values(&keyword.value)
    });
    if autouse_active && params_with_values {
        issues.push(issue_at(RULE_KEY, MESSAGE, range, index, source));
    }
}

/// The literal `True` spelling from the rule description; `False`,
/// `None`, and non-literal expressions stay silent.
fn is_boolean_true(expr: &Expr) -> bool {
    matches!(expr, Expr::BooleanLiteral(literal) if literal.value)
}

/// Whether `params` carries values: everything except `None` and empty
/// list, tuple, set, and dict literals. Non-literal expressions may
/// evaluate to values at runtime and are treated as populated.
fn carries_values(expr: &Expr) -> bool {
    match expr {
        Expr::NoneLiteral(_) => false,
        Expr::List(list) => !list.elts.is_empty(),
        Expr::Tuple(tuple) => !tuple.elts.is_empty(),
        Expr::Set(set) => !set.elts.is_empty(),
        Expr::Dict(dict) => !dict.items.is_empty(),
        _ => true,
    }
}
