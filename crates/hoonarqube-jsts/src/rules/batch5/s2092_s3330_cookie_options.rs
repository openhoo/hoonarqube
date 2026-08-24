use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::boolean_property;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::RuleScope;
use crate::support::expression_root_name;
use crate::support::unparenthesized;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S2092` and `S3330`: cookie options missing `secure` / `httpOnly`.
    pub(crate) fn check_cookie_options(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        let property: &str = &member.property.name;
        let rooted_at_response = matches!(
            expression_root_name(&member.object),
            Some("res" | "response")
        );
        if property != "cookie" || !rooted_at_response || call.arguments.len() < 3 {
            return;
        }
        let Some(options) = call.arguments.get(2).and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(object) = unparenthesized(options) else {
            return;
        };
        if boolean_property(object, "secure") != Some(true) {
            self.sink.emit_span(
                RuleScope::Both,
                "S2092",
                "Set the 'secure' cookie option to true.",
                call.span(),
            );
        }
        if boolean_property(object, "httpOnly") != Some(true) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3330",
                "Set the 'httpOnly' cookie option to true.",
                call.span(),
            );
        }
    }
}
