use crate::rules::batch5::collectors::{SecurityHotspotCollector, SecurityModule, object_property};
use crate::rules::shared::argument_expression;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::{CallExpression, Expression};
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S4502`: CSRF protection switched off or omitted for state-changing routes.
    pub(crate) fn check_csrf_disabled(&mut self, call: &CallExpression<'_>) {
        let at = call.span().start;
        if self
            .security_bindings
            .is_module(&call.callee, SecurityModule::Csurf, at)
            && let Some(argument) = call.arguments.first().and_then(argument_expression)
            && let Expression::ObjectExpression(object) = unparenthesized(argument)
            && let Some(Expression::ArrayExpression(routes)) =
                object_property(object, "ignoreRoutes")
            && !routes.elements.is_empty()
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4502",
                "Make sure disabling CSRF protection for these routes is safe.",
                call.span(),
            );
        }
    }
}
