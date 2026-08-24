use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::first_string_argument;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::RuleScope;
use crate::support::span_text_contains;
use crate::support::unparenthesized;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S2819`: message handlers that never consult `origin`.
    pub(crate) fn check_message_handler(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        if !(member.property.name == "on" || member.property.name == "addEventListener") {
            return;
        }
        let Some(channel) = first_string_argument(call) else {
            return;
        };
        if !matches!(channel, "message" | "onmessage") {
            return;
        }
        let Some(handler) = call.arguments.get(1).and_then(argument_expression) else {
            return;
        };
        let body_span = match unparenthesized(handler) {
            Expression::FunctionExpression(function) => {
                function.body.as_deref().map(oxc_span::GetSpan::span)
            }
            Expression::ArrowFunctionExpression(arrow) => Some(arrow.body.span()),
            _ => None,
        };
        let Some(body_span) = body_span else {
            return;
        };
        if span_text_contains(self.source, body_span, "origin") {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S2819",
            "Make sure this message handler verifies the sender origin.",
            call.span(),
        );
    }
}
