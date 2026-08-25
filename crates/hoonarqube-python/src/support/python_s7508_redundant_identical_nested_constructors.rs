// --- python:S7508 — redundant identical nested constructors

use crate::support::{for_each_expr, for_each_stmt, stmt_exprs, string_value_text};
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;

// ---------------------------------------------------------------------------
// Tier-A battery entries #111–#193 (python:S1192 … python:S7489).
//
// One private check per catalog entry, aggregated through
// `check_tier_a_battery_2`. Detection follows the batch spec: single-file
// AST/token/text heuristics with deliberately conservative predicates.
// ---------------------------------------------------------------------------

/// Dotted path of a pure `a.b.c` chain rooted at a name; calls and other
/// expressions break the chain.
pub(crate) fn dotted_name(expr: &Expr) -> Option<String> {
    match expr {
        Expr::Name(name) => Some(name.id.as_str().to_string()),
        Expr::Attribute(attr) => Some(format!(
            "{}.{}",
            dotted_name(&attr.value)?,
            attr.attr.as_str()
        )),
        _ => None,
    }
}

/// `(dotted callee path, arguments)` of a call whose callee is a plain name
/// or a dotted attribute chain.
pub(crate) fn call_parts(expr: &Expr) -> Option<(String, &ruff_python_ast::Arguments)> {
    match expr {
        Expr::Call(call) => dotted_name(&call.func).map(|path| (path, &call.arguments)),
        _ => None,
    }
}

pub(crate) fn keyword_value<'a>(
    arguments: &'a ruff_python_ast::Arguments,
    name: &str,
) -> Option<&'a Expr> {
    arguments.keywords.iter().find_map(|keyword| {
        let arg = keyword.arg.as_ref()?;
        (arg.as_str() == name).then_some(&keyword.value)
    })
}

pub(crate) fn has_keyword(arguments: &ruff_python_ast::Arguments, name: &str) -> bool {
    keyword_value(arguments, name).is_some()
}

pub(crate) fn is_true_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::BooleanLiteral(literal) if literal.value)
}

pub(crate) fn is_false_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::BooleanLiteral(literal) if !literal.value)
}

pub(crate) fn int_literal_value(expr: &Expr) -> Option<i64> {
    match expr {
        Expr::NumberLiteral(number) => match &number.value {
            ruff_python_ast::Number::Int(value) => value.as_i64(),
            _ => None,
        },
        _ => None,
    }
}

/// Decoded text of a plain (non-f-string, non-bytes) string literal.
pub(crate) fn string_literal_text(expr: &Expr) -> Option<String> {
    match expr {
        Expr::StringLiteral(literal) => Some(string_value_text(&literal.value)),
        _ => None,
    }
}

/// Root name of a pure attribute chain (`df` in `df.groupby(...)`).
pub(crate) fn receiver_root(expr: &Expr) -> Option<&str> {
    match expr {
        Expr::Name(name) => Some(name.id.as_str()),
        Expr::Attribute(attr) => receiver_root(&attr.value),
        Expr::Call(call) => receiver_root(&call.func),
        _ => None,
    }
}

/// Visits every call reachable from a statement tree, including calls nested
/// in expressions and compound-statement headers.
pub(crate) fn for_each_call(
    module_body: &[Stmt],
    visit: &mut impl FnMut(&ruff_python_ast::ExprCall),
) {
    for_each_stmt(module_body, &mut |stmt| {
        for expr in stmt_exprs(stmt) {
            for_each_expr(expr, &mut |expr| {
                if let Expr::Call(call) = expr {
                    visit(call);
                }
            });
        }
    });
}

/// Whether the module shows evidence of an actual boto3 client/resource
/// binding: a `boto3.client`/`boto3.resource` call, a `boto3.Session`
/// construction, or `.client(`/`.resource(` reached through a `boto3` or
/// session object. The AWS/cdk-family checks only evaluate calls on
/// resolvable boto3 clients, so they stay silent without such a binding
/// (stub objects like `client = object()` never qualify).
pub(crate) fn has_boto3_binding(module_body: &[Stmt]) -> bool {
    let mut found = false;
    for_each_call(module_body, &mut |call| {
        if found {
            return;
        }
        let Expr::Attribute(attribute) = &*call.func else {
            return;
        };
        match attribute.attr.as_str() {
            "client" | "resource" => {
                found = expr_chain_mentions(&attribute.value, &["boto3", "session"]);
            }
            "Session" => found = expr_chain_mentions(&attribute.value, &["boto3"]),
            _ => {}
        }
    });
    found
}

/// Whether any name inside the expression tree equals one of `names`.
fn expr_chain_mentions(expr: &Expr, names: &[&str]) -> bool {
    let mut found = false;
    for_each_expr(expr, &mut |child| {
        if let Expr::Name(name) = child {
            found |= names.contains(&name.id.as_str());
        }
    });
    found
}

pub(crate) fn is_standalone_string_stmt(stmt: &Stmt) -> bool {
    matches!(stmt, Stmt::Expr(expr) if matches!(expr.value.as_ref(), Expr::StringLiteral(_)))
}

/// Naive matcher for the `exclusionRegex` option: a plain substring when the
/// pattern is free of regex metacharacters, otherwise no exclusion.
pub(crate) fn excluded_by_pattern(pattern: &str, value: &str) -> bool {
    !pattern.is_empty()
        && !pattern.chars().any(|c| "\\^$.|?*+()[]{}".contains(c))
        && value.contains(pattern)
}
