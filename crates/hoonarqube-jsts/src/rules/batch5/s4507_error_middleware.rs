use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::RuleScope;
use crate::support::expression_root_name;
use crate::support::unparenthesized;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S4507`: error-handling middleware mounted outside debug guards.
    pub(crate) fn check_error_middleware(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        let property: &str = &member.property.name;
        if property != "use" || expression_root_name(&member.object) != Some("app") {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let flagged = match unparenthesized(argument) {
            Expression::Identifier(identifier) => identifier.name == "errorHandler",
            Expression::StringLiteral(literal) => literal.value.as_str() == "errorHandler",
            _ => false,
        };
        if flagged {
            self.sink.emit_span(
                RuleScope::Both,
                "S4507",
                "Only enable this error-handling middleware while debugging.",
                call.span(),
            );
        }
    }
}
