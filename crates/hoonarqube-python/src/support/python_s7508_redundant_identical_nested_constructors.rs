// --- python:S7508 — redundant identical nested constructors

use crate::support::{for_each_expr, for_each_stmt, stmt_exprs, string_value_text};
use ruff_python_ast::Expr;
use ruff_python_ast::Stmt;
use ruff_text_size::Ranged;
use ruff_text_size::TextRange;

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

/// Segments of a pure `a.b.c` chain, root first; `None` when any link is a
/// non-Name/non-Attribute expression (identical acceptance as [`dotted_name`]).
fn dotted_segments(expr: &Expr) -> Option<Vec<&str>> {
    let mut segments = Vec::new();
    let mut cursor = expr;
    loop {
        match cursor {
            Expr::Name(name) => {
                segments.push(name.id.as_str());
                segments.reverse();
                return Some(segments);
            }
            Expr::Attribute(attr) => {
                segments.push(attr.attr.as_str());
                cursor = &attr.value;
            }
            _ => return None,
        }
    }
}

/// Allocation-free equivalent of `dotted_name(expr).as_deref() == Some(expected)`.
pub(crate) fn dotted_name_is(expr: &Expr, expected: &str) -> bool {
    dotted_segments(expr).is_some_and(|segments| segments.iter().copied().eq(expected.split('.')))
}

/// Allocation-free equivalent of
/// `dotted_name(expr).is_some_and(|p| candidates.contains(&p.as_str()))`.
pub(crate) fn dotted_name_in(expr: &Expr, candidates: &[&str]) -> bool {
    candidates
        .iter()
        .copied()
        .any(|candidate| dotted_name_is(expr, candidate))
}

/// Allocation-free equivalent of `dotted_name(expr).is_some_and(|p|
/// p.starts_with(prefix))` for a `prefix` that includes the trailing dot.
pub(crate) fn dotted_name_starts_with(expr: &Expr, prefix: &str) -> bool {
    debug_assert!(prefix.ends_with('.'), "prefix must end with '.'");
    let Some(stem) = prefix.strip_suffix('.') else {
        return false;
    };
    let Some(segments) = dotted_segments(expr) else {
        return false;
    };
    let mut parts = stem.split('.');
    let mut matched = 0usize;
    for (segment, part) in segments.iter().copied().zip(&mut parts) {
        if segment != part {
            return false;
        }
        matched += 1;
    }
    parts.next().is_none() && segments.len() > matched
}

/// Allocation-free equivalent of `dotted_name(expr).is_some_and(|p|
/// p.rsplit_once('.').is_some_and(|(head, _)| candidates.contains(&head)))`:
/// the full path minus its final segment is one of `candidates`.
pub(crate) fn dotted_name_parent_in(expr: &Expr, candidates: &[&str]) -> bool {
    let Some(segments) = dotted_segments(expr) else {
        return false;
    };
    if segments.len() < 2 {
        return false;
    }
    let parent = &segments[..segments.len() - 1];
    candidates
        .iter()
        .any(|candidate| parent.iter().copied().eq(candidate.split('.')))
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

pub(crate) fn keyword_range(
    arguments: &ruff_python_ast::Arguments,
    name: &str,
) -> Option<TextRange> {
    arguments.keywords.iter().find_map(|keyword| {
        let arg = keyword.arg.as_ref()?;
        (arg.as_str() == name).then(|| keyword.range())
    })
}

pub(crate) fn wildcard_literal(value: &Expr) -> Option<&Expr> {
    match value {
        Expr::List(list) => list.elts.iter().find_map(wildcard_literal),
        Expr::Tuple(tuple) => tuple.elts.iter().find_map(wildcard_literal),
        Expr::StringLiteral(_) if string_literal_text(value).as_deref() == Some("*") => Some(value),
        _ => None,
    }
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
