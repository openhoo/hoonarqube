// --- python:S6919 / python:S6974 — Keras Model / BaseEstimator subclass contracts

use crate::support::{called_name, dotted_name};
use ruff_python_ast::Expr;

pub(crate) fn class_base_paths(class: &ruff_python_ast::StmtClassDef) -> Vec<String> {
    class
        .arguments
        .as_ref()
        .map(|arguments| arguments.args.iter().filter_map(dotted_name).collect())
        .unwrap_or_default()
}

pub(crate) fn base_tail_is(path: &str, tail: &str) -> bool {
    path.rsplit('.').next() == Some(tail)
}

pub(crate) fn is_super_init_call(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(call)
        if matches!(call.func.as_ref(), Expr::Attribute(attr)
            if attr.attr.as_str() == "__init__"
                && matches!(attr.value.as_ref(), Expr::Call(outer)
                    if called_name(&outer.func) == Some("super"))))
}

pub(crate) fn is_self_attribute(target: &Expr, tail_predicate: impl Fn(&str) -> bool) -> bool {
    matches!(target, Expr::Attribute(attribute)
        if matches!(attribute.value.as_ref(), Expr::Name(name) if name.id.as_str() == "self")
            && tail_predicate(attribute.attr.as_str()))
}

/// Einops pattern grammar subset: one `->`, balanced parentheses per side,
/// identifier/ellipsis/`1` tokens only, identical multisets on both sides.
pub(crate) fn einops_pattern_error(pattern: &str) -> Option<&'static str> {
    let sides: Vec<&str> = pattern.splitn(2, "->").collect();
    if sides.len() != 2 {
        return Some("expected exactly one '->'");
    }
    let mut token_lists: Vec<Vec<&str>> = Vec::new();
    for side in sides {
        let mut depth: i64 = 0;
        let mut tokens: Vec<&str> = Vec::new();
        for token in side.split_whitespace() {
            let valid = token == "..." || token.chars().all(|c| c.is_alphanumeric() || c == '_');
            if !valid {
                return Some("invalid token");
            }
            for ch in token.chars() {
                match ch {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    _ => {}
                }
                if depth < 0 {
                    return Some("unbalanced parentheses");
                }
            }
            tokens.push(token);
        }
        if depth != 0 {
            return Some("unbalanced parentheses");
        }
        tokens.sort_unstable();
        token_lists.push(tokens);
    }
    if token_lists[0] != token_lists[1] {
        return Some("axis names must match on both sides");
    }
    None
}
