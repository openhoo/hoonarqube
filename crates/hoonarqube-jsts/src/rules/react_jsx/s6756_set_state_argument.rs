use super::walker::{ReactCollector, ThisStateReferenceScanner};
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::RuleScope;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6756`: `this.setState` arguments reaching into `this.state`
    /// instead of using the updater form.
    pub(crate) fn check_set_state_argument(&mut self, call: &CallExpression<'_>) {
        let is_method_call = matches!(
            &call.callee,
            Expression::StaticMemberExpression(member)
                if member.property.name == "setState"
                    && matches!(&member.object, Expression::ThisExpression(_))
        );
        if !is_method_call {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let mut scanner = ThisStateReferenceScanner::default();
        scanner.visit_expression(argument);
        if scanner.found {
            self.sink.emit_span(
                RuleScope::Both,
                "S6756",
                "Use the updater form of 'setState'; reading 'this.state' during the update misses batching.",
                call.span(),
            );
        }
    }
}
