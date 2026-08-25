// --- python:S2092 / S3330 — cookie "secure" and "HttpOnly" flags

/// `set_cookie` calls that do not pass `<flag>=True` (missing or literal
/// `False`); both Flask and Django expose this exact API shape.
pub(crate) fn cookie_flag_missing(call: &ruff_python_ast::ExprCall, flag: &str) -> bool {
    is_call_method(call, "set_cookie")
        && !keyword_value(&call.arguments, flag).is_some_and(is_true_literal)
}

use crate::support::{is_call_method, is_true_literal, keyword_value};
