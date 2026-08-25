// --- python:S5247 / S5439 — HTML autoescaping disabled

/// Jinja shapes that switch autoescaping off.
pub(crate) fn autoescape_off(call: &ruff_python_ast::ExprCall) -> bool {
    const AUTOESCAPE_ENGINES: [&str; 2] = ["Environment", "select_autoescape"];
    AUTOESCAPE_ENGINES.contains(&called_name(&call.func).unwrap_or_default())
        && (keyword_value(&call.arguments, "autoescape").is_some_and(is_false_literal)
            || keyword_value(&call.arguments, "enabled").is_some_and(is_false_literal))
}

use crate::support::{called_name, is_false_literal, keyword_value};
