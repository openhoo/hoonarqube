use crate::support::{dotted_name_is, for_each_stmt_expr, is_zero_number_literal, issue_at};
use hoonarqube_ir::Issue;
use ruff_python_ast::{Expr, ModModule};
use ruff_python_parser::Parsed;
use ruff_source_file::LineIndex;
use ruff_text_size::Ranged;

const RULE_KEY: &str = "python:S9075";
const MESSAGE: &str =
    "This assertion is too broad; use a more specific warning type or check the warning message.";

/// python:S9075 — a `pytest.warns()` assertion that verifies only *some*
/// warning: a bare call (no expected warning type and no `match=`), or the
/// base `Warning` type (directly, or as an element of a tuple) without a
/// `match=`. A specific warning type is accepted without `match=`, and a
/// non-falsy `match=` narrows the expectation even without a type. The bare
/// call anchors on the call; a broad type argument anchors on that argument.
pub(crate) fn check_s9075_specific_warning_assertion(
    parsed: &Parsed<ModModule>,
    index: &LineIndex,
    source: &str,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    for_each_stmt_expr(parsed.syntax().body.as_slice(), &mut |expr| {
        let Expr::Call(call) = expr else {
            return;
        };
        if !dotted_name_is(&call.func, "pytest.warns") {
            return;
        }
        if has_effective_match(call) {
            return;
        }
        match warning_argument(call) {
            // No expected-warning argument at all: the call itself anchors.
            None => issues.push(issue_at(RULE_KEY, MESSAGE, call.range(), index, source)),
            Some(warning) => {
                if let Some(range) = broad_warning_range(warning) {
                    issues.push(issue_at(RULE_KEY, MESSAGE, range, index, source));
                }
            }
        }
    });
    issues
}

/// First positional argument of the call, unless it is a starred expression,
/// which leaves the expected-warning set unresolved.
fn warning_argument(call: &ruff_python_ast::ExprCall) -> Option<&Expr> {
    match call.arguments.args.first()? {
        Expr::Starred(_) => None,
        argument => Some(argument),
    }
}

/// A `match=` keyword whose value is not a falsy literal narrows the
/// expectation. Non-literal values stay effective.
fn has_effective_match(call: &ruff_python_ast::ExprCall) -> bool {
    call.arguments
        .keywords
        .iter()
        .any(|keyword| keyword.arg.as_deref() == Some("match") && !is_falsy_literal(&keyword.value))
}

fn is_falsy_literal(expr: &Expr) -> bool {
    match expr {
        Expr::NoneLiteral(_) => true,
        Expr::StringLiteral(string) => string.value.is_empty(),
        Expr::List(list) => list.elts.is_empty(),
        Expr::Tuple(tuple) => tuple.elts.is_empty(),
        Expr::Dict(dict) => dict.is_empty(),
        Expr::Set(set) => set.elts.is_empty(),
        Expr::NumberLiteral(_) => is_zero_number_literal(expr),
        _ => false,
    }
}

/// A warning-type expression is too broad when it names the base `Warning`
/// class; tuple/list forms report their first broad element.
fn broad_warning_range(expr: &Expr) -> Option<ruff_text_size::TextRange> {
    match expr {
        Expr::List(list) => list.elts.iter().find_map(broad_warning_range),
        Expr::Tuple(tuple) => tuple.elts.iter().find_map(broad_warning_range),
        Expr::Name(name) => (name.id.as_str() == "Warning").then_some(name.range()),
        Expr::Attribute(attribute) => {
            (attribute.attr.as_str() == "Warning").then_some(attribute.range())
        }
        _ => None,
    }
}
