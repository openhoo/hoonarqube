use crate::rules::batch5::collectors::ANGULAR_BYPASS_METHODS;
use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::shared::sink_callee_name;
use crate::support::RuleScope;
use oxc_ast::ast::{CallExpression, Expression};
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S6268`: Angular sanitizer bypass methods.
    pub(crate) fn check_angular_bypass(&mut self, call: &CallExpression<'_>) {
        let Some(name) = sink_callee_name(&call.callee) else {
            return;
        };
        if ANGULAR_BYPASS_METHODS.contains(&name) {
            let anchor = match &call.callee {
                Expression::StaticMemberExpression(member) => member.property.span(),
                _ => call.callee.span(),
            };
            self.sink.emit_span(
                RuleScope::Both,
                "S6268",
                "Make sure disabling Angular built-in sanitization is safe here.",
                anchor,
            );
        }
    }
}
