use crate::rules::batch5::collectors::SENSITIVE_DATA_FRAGMENTS;
use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::shared::CONSOLE_METHODS;
use crate::rules::shared::argument_expression;
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
            // ASCII-insensitive scan over the borrowed span text; identical
            // matches to the former `to_ascii_lowercase().contains(...)`
            // (the ASCII lowercase map preserves byte positions) without a
            // lowered copy per argument.
            let text = span_text(self.source, expression.span());
            SENSITIVE_DATA_FRAGMENTS.iter().any(|fragment| {
                crate::support::contains_ascii_case_insensitive(
                    text.as_bytes(),
                    fragment.as_bytes(),
                )
            })
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
