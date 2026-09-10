use crate::rules::batch5::collectors::{SecurityFactory, SecurityHotspotCollector};
use crate::rules::shared::argument_expression;
use crate::support::RuleScope;
use oxc_ast::ast::{CallExpression, Expression};
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S4507`: error-handling middleware mounted outside debug guards.
    pub(crate) fn check_error_middleware(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        if member.property.name != "use"
            || !self.security_bindings.is_factory(
                &member.object,
                SecurityFactory::ExpressApp,
                call.span().start,
            )
        {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        if !self.security_bindings.is_factory(
            argument,
            SecurityFactory::ErrorMiddleware,
            call.span().start,
        ) || self.in_development_guard(call.span())
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S4507",
            "Only enable this error-handling middleware while debugging.",
            call.span(),
        );
    }
}
