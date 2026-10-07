// --- python:S2092 / S3330 — cookie "secure" and "HttpOnly" flags

/// Missing flags and explicit false flag literals report; dynamic values
/// remain unknown and are not guessed to be disabled.
pub(crate) fn cookie_flag_missing(
    call: &ruff_python_ast::ExprCall,
    flag: &str,
    position: Option<usize>,
) -> bool {
    is_call_method(call, "set_cookie")
        && match position
            .and_then(|index| call.arguments.args.get(index))
            .or_else(|| keyword_value(&call.arguments, flag))
        {
            None => true,
            Some(ruff_python_ast::Expr::BooleanLiteral(value)) => !value.value,
            Some(_) => false,
        }
}

use crate::support::{is_call_method, keyword_value};
