use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::shared::argument_expression;
use crate::rules::shared::sink_callee_name;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S5148`: `window.open` features strings lacking `noopener`.
    pub(crate) fn check_window_open(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) != Some("open") || call.arguments.len() < 3 {
            return;
        }
        let Some(features) = call.arguments.get(2).and_then(argument_expression) else {
            return;
        };
        let Expression::StringLiteral(literal) = unparenthesized(features) else {
            return;
        };
        let lowered = literal.value.to_ascii_lowercase();
        if !lowered.contains("noopener") && !lowered.contains("noreferrer") {
            self.sink.emit_span(
                RuleScope::Both,
                "S5148",
                "Add 'noopener' to this window.open features string.",
                call.span(),
            );
        }
    }
}
