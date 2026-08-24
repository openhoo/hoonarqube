use super::walker::{ReactCollector, capitalize_first, is_state_setter_name};
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::RuleScope;
use crate::support::callee_name;
use crate::support::identifier_name;
use oxc_ast::ast::CallExpression;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6443`: `setX(x)` calls passing the state variable back to its own
    /// setter.
    pub(crate) fn check_noop_state_setter(&mut self, call: &CallExpression<'_>) {
        let Some(callee) = callee_name(call) else {
            return;
        };
        if !is_state_setter_name(callee) || call.arguments.len() != 1 {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Some(name) = identifier_name(argument) else {
            return;
        };
        if capitalize_first(name) == callee[3..] {
            self.sink.emit_span(
                RuleScope::Both,
                "S6443",
                "Pass a different value or an updater function; setting the state to itself changes nothing.",
                call.span(),
            );
        }
    }
}
