use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::object_property;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::rules::tier_c::walker::sink_callee_name;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S4502`: CSRF protection switched off for explicit route lists.
    pub(crate) fn check_csrf_disabled(&mut self, call: &CallExpression<'_>) {
        if !matches!(sink_callee_name(&call.callee), Some("csrf" | "csurf")) {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(object) = unparenthesized(argument) else {
            return;
        };
        let Some(Expression::ArrayExpression(routes)) = object_property(object, "ignoreRoutes")
        else {
            return;
        };
        if !routes.elements.is_empty() {
            self.sink.emit_span(
                RuleScope::Both,
                "S4502",
                "Make sure disabling CSRF protection for these routes is safe.",
                call.span(),
            );
        }
    }
}
