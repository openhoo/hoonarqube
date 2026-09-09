use super::collectors::PromiseFlowCollector;
use crate::rules::shared::argument_expression;
use crate::support::RuleScope;
use crate::support::binding_identifier_name;
use crate::support::identifier_name;
use crate::support::statement_as_expression;
use crate::support::unparenthesized;
use oxc_ast::ast::Expression;
use oxc_ast::ast::FunctionBody;
use oxc_ast::ast::NewExpression;
use oxc_span::GetSpan;

/// Whether the executor's one expression statement settles through one of its
/// first two parameters. Position, not parameter spelling, selects the action.
fn settles_immediately(
    body: &FunctionBody<'_>,
    resolve: Option<&str>,
    reject: Option<&str>,
) -> Option<&'static str> {
    if body.statements.len() != 1 {
        return None;
    }
    let expression = statement_as_expression(&body.statements[0])?;
    let Expression::CallExpression(call) = unparenthesized(expression) else {
        return None;
    };
    if call.arguments.len() != 1 {
        return None;
    }
    let callee = identifier_name(unparenthesized(&call.callee))?;
    if resolve == Some(callee) {
        Some("resolve")
    } else if reject == Some(callee) {
        Some("reject")
    } else {
        None
    }
}

/// Whether a `new Promise` executor settles immediately. The first parameter
/// is always resolve and the second parameter is always reject.
fn promise_executor_settles_immediately(argument: &Expression<'_>) -> Option<&'static str> {
    match unparenthesized(argument) {
        Expression::FunctionExpression(function) => {
            let body = function.body.as_deref()?;
            let resolve = function
                .params
                .items
                .first()
                .and_then(|item| binding_identifier_name(&item.pattern));
            let reject = function
                .params
                .items
                .get(1)
                .and_then(|item| binding_identifier_name(&item.pattern));
            settles_immediately(body, resolve, reject)
        }
        Expression::ArrowFunctionExpression(arrow) => {
            let resolve = arrow
                .params
                .items
                .first()
                .and_then(|item| binding_identifier_name(&item.pattern));
            let reject = arrow
                .params
                .items
                .get(1)
                .and_then(|item| binding_identifier_name(&item.pattern));
            if let Some(body) = arrow.body.as_function_body() {
                settles_immediately(body, resolve, reject)
            } else {
                let Expression::CallExpression(call) = unparenthesized(arrow.body.to_expression())
                else {
                    return None;
                };
                if call.arguments.len() != 1 {
                    return None;
                }
                let callee = identifier_name(unparenthesized(&call.callee))?;
                if resolve == Some(callee) {
                    Some("resolve")
                } else if reject == Some(callee) {
                    Some("reject")
                } else {
                    None
                }
            }
        }
        _ => None,
    }
}

// Generated per-rule checks (moved out of traversal overrides).
impl PromiseFlowCollector<'_> {
    /// `S4634` logic extracted from `visit_new_expression`.
    pub(crate) fn check_s4634_new_expression(&mut self, it: &NewExpression<'_>) {
        if identifier_name(&it.callee) == Some("Promise")
            && it.arguments.len() == 1
            && let Some(argument) = it.arguments.first().and_then(argument_expression)
            && let Some(action) = promise_executor_settles_immediately(argument)
        {
            let message = match action {
                "resolve" => "Replace this trivial promise with \"Promise.resolve\".",
                "reject" => "Replace this trivial promise with \"Promise.reject\".",
                _ => return,
            };
            self.sink
                .emit_span(RuleScope::Both, "S4634", message, it.callee.span());
        }
    }
}
