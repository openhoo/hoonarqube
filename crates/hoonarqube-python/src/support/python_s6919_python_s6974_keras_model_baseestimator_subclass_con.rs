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
    let Some((left, right)) = pattern.split_once("->") else {
        return Some("expected exactly one '->'");
    };
    if right.contains("->") {
        return Some("expected exactly one '->'");
    }
    let mut left_axes = match parse_einops_side(left) {
        Ok(axes) => axes,
        Err(error) => return Some(error),
    };
    let mut right_axes = match parse_einops_side(right) {
        Ok(axes) => axes,
        Err(error) => return Some(error),
    };
    left_axes.sort_unstable();
    right_axes.sort_unstable();
    if left_axes != right_axes {
        return Some("axis names must match on both sides");
    }
    None
}

fn parse_einops_side(side: &str) -> Result<Vec<&str>, &'static str> {
    let mut depth = 0_i64;
    let mut token_start = None;
    let mut axes = Vec::new();
    for (position, character) in side.char_indices() {
        match character {
            '(' => {
                push_einops_axis(side, &mut token_start, position, &mut axes)?;
                depth += 1;
            }
            ')' => {
                push_einops_axis(side, &mut token_start, position, &mut axes)?;
                depth -= 1;
                if depth < 0 {
                    return Err("unbalanced parentheses");
                }
            }
            whitespace if whitespace.is_whitespace() => {
                push_einops_axis(side, &mut token_start, position, &mut axes)?;
            }
            character if character.is_alphanumeric() || matches!(character, '_' | '.') => {
                token_start.get_or_insert(position);
            }
            _ => return Err("invalid token"),
        }
    }
    push_einops_axis(side, &mut token_start, side.len(), &mut axes)?;
    if depth == 0 {
        Ok(axes)
    } else {
        Err("unbalanced parentheses")
    }
}

fn push_einops_axis<'a>(
    side: &'a str,
    token_start: &mut Option<usize>,
    end: usize,
    axes: &mut Vec<&'a str>,
) -> Result<(), &'static str> {
    let Some(start) = token_start.take() else {
        return Ok(());
    };
    let token = &side[start..end];
    let valid = token == "..." || token.chars().all(|c| c.is_alphanumeric() || c == '_');
    if !valid {
        return Err("invalid token");
    }
    if token != "1" {
        axes.push(token);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::einops_pattern_error;

    #[test]
    fn einops_parser_accepts_grouped_axes_ellipsis_and_unit_dimensions() {
        assert_eq!(
            einops_pattern_error("b (h p1) (w p2) c -> b h w (p1 p2 c)"),
            None
        );
        assert_eq!(einops_pattern_error("... c -> c ..."), None);
        assert_eq!(einops_pattern_error("b c -> b 1 c"), None);
    }

    #[test]
    fn einops_parser_rejects_bad_tokens_arrows_and_parentheses() {
        assert_eq!(einops_pattern_error("b $ -> b"), Some("invalid token"));
        assert_eq!(
            einops_pattern_error("b -> b -> b"),
            Some("expected exactly one '->'")
        );
        assert_eq!(
            einops_pattern_error("b (h w -> b h w"),
            Some("unbalanced parentheses")
        );
    }
}
