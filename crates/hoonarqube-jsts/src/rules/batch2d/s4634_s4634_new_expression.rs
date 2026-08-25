use super::collectors::PromiseFlowCollector;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::RuleScope;
use crate::support::binding_identifier_name;
use crate::support::identifier_name;
use crate::support::statement_as_expression;
use crate::support::unparenthesized;
use oxc_ast::ast::Expression;
use oxc_ast::ast::FunctionBody;
use oxc_ast::ast::NewExpression;
use oxc_span::GetSpan;

/// Whether every top-level statement of the executor immediately calls its
/// own resolve/reject parameter.
fn settles_immediately(body: &FunctionBody<'_>, param: &str) -> bool {
    !body.statements.is_empty()
        && body.statements.iter().all(|statement| {
            statement_as_expression(statement).is_some_and(|expression| {
                matches!(unparenthesized(expression), Expression::CallExpression(call)
                    if identifier_name(&call.callee) == Some(param))
            })
        })
}

/// Whether a `new Promise` executor argument settles the promise without
/// doing any asynchronous work: every block statement is an immediate call
/// of its own resolve/reject parameter, or (for expression-bodied arrows)
/// the whole body is that call.
fn promise_executor_settles_immediately(argument: &Expression<'_>) -> bool {
    match argument {
        Expression::FunctionExpression(function) => {
            let Some(body) = function.body.as_deref() else {
                return false;
            };
            let Some(param) = function
                .params
                .items
                .first()
                .and_then(|item| binding_identifier_name(&item.pattern))
            else {
                return false;
            };
            settles_immediately(body, param)
        }
        Expression::ArrowFunctionExpression(arrow) => {
            let Some(param) = arrow
                .params
                .items
                .first()
                .and_then(|item| binding_identifier_name(&item.pattern))
            else {
                return false;
            };
            match arrow.body.as_function_body() {
                Some(body) => settles_immediately(body, param),
                None => matches!(arrow.body.to_expression(), Expression::CallExpression(call)
                    if identifier_name(&call.callee) == Some(param)),
            }
        }
        _ => false,
    }
}

// Generated per-rule checks (moved out of traversal overrides).
impl PromiseFlowCollector<'_> {
    /// `S4634` logic extracted from `visit_new_expression`.
    pub(crate) fn check_s4634_new_expression(&mut self, it: &NewExpression<'_>) {
        if identifier_name(&it.callee) == Some("Promise")
            && let Some(argument) = it.arguments.first().and_then(argument_expression)
            && promise_executor_settles_immediately(argument)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4634",
                "Refactor this promise executor; it resolves or rejects immediately.",
                it.span(),
            );
        }
    }
}
