use crate::rules::batch5::s2187_test_framework_rules::TestFrameworkCollector;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl TestFrameworkCollector<'_, '_> {
    /// `S6080`: disabled timeouts via `this.timeout(0)`.
    pub(crate) fn check_this_timeout_zero(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        if member.property.name != "timeout"
            || !matches!(&member.object, Expression::ThisExpression(_))
        {
            return;
        }
        let zero = call
            .arguments
            .first()
            .and_then(argument_expression)
            .is_some_and(|argument| {
                matches!(
                    unparenthesized(argument),
                    Expression::NumericLiteral(literal) if literal.value == 0.0
                )
            });
        if zero {
            self.sink.emit_span(
                RuleScope::Both,
                "S6080",
                "Avoid disabling test timeouts with 'this.timeout(0)'.",
                call.span(),
            );
        }
    }
}
