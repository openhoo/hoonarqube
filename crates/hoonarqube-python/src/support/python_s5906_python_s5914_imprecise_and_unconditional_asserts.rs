// --- python:S5906 / python:S5914 — imprecise and unconditional asserts

use crate::support::called_name;
use ruff_python_ast::Expr;

pub(crate) fn unconditional_assert_verdict(
    call: &ruff_python_ast::ExprCall,
    _source: &str,
) -> Option<&'static str> {
    let args = &call.arguments.args;
    // CE flags only constant boolean literals in assertTrue/assertFalse;
    // `assertEqual(x, x)` forms are beyond the CE engine's scope.
    match called_name(&call.func) {
        Some("assertTrue") if args.len() == 1 => match &args[0] {
            Expr::BooleanLiteral(literal) if literal.value => Some("passes"),
            Expr::BooleanLiteral(_) => Some("fails"),
            _ => None,
        },
        Some("assertFalse") if args.len() == 1 => match &args[0] {
            Expr::BooleanLiteral(literal) if !literal.value => Some("passes"),
            Expr::BooleanLiteral(_) => Some("fails"),
            _ => None,
        },
        _ => None,
    }
}
