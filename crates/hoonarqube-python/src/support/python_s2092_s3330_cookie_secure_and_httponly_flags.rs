// --- python:S2092 / S3330 — cookie "secure" and "HttpOnly" flags

/// Missing cookie flags report; an explicit false secure flag also reports.
/// HttpOnly accepts any present argument under its separate rule contract.
pub(crate) fn cookie_flag_missing(call: &ruff_python_ast::ExprCall, flag: &str) -> bool {
    is_call_method(call, "set_cookie")
        && match keyword_value(&call.arguments, flag) {
            None => true,
            Some(ruff_python_ast::Expr::BooleanLiteral(value)) if flag == "secure" => !value.value,
            Some(_) => false,
        }
}

use crate::support::{is_call_method, keyword_value};
