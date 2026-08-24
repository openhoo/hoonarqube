use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::support::RuleScope;
use crate::support::expression_root_name;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S2245`: nondeterministic randomness worth reviewing.
    pub(crate) fn check_math_random(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        if member.property.name == "random" && expression_root_name(&member.object) == Some("Math")
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S2245",
                "Make sure using 'Math.random()' is safe here.",
                call.span(),
            );
        }
    }
}
