use crate::rules::batch5::collectors::SENSITIVE_DATA_FRAGMENTS;
use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::expression::collectors::CONSOLE_METHODS;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::RuleScope;
use crate::support::expression_root_name;
use crate::support::span_text;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S5757`: console logging of sensitive-looking values.
    pub(crate) fn check_sensitive_log(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        let property: &str = &member.property.name;
        if expression_root_name(&member.object) != Some("console")
            || !CONSOLE_METHODS.contains(&property)
        {
            return;
        }
        let sensitive = call.arguments.iter().any(|argument| {
            let Some(expression) = argument_expression(argument) else {
                return false;
            };
            let text = span_text(self.source, expression.span()).to_ascii_lowercase();
            SENSITIVE_DATA_FRAGMENTS
                .iter()
                .any(|fragment| text.contains(fragment))
        });
        if sensitive {
            self.sink.emit_span(
                RuleScope::Both,
                "S5757",
                "Make sure this logged data is not sensitive.",
                call.span(),
            );
        }
    }
}
