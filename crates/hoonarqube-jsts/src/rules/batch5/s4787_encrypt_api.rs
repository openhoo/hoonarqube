use crate::rules::batch5::collectors::ENCRYPT_API_NAMES;
use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::tier_c::walker::sink_callee_name;
use crate::support::RuleScope;
use oxc_ast::ast::CallExpression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S4787`: encryption API usage worth reviewing.
    pub(crate) fn check_encrypt_api(&mut self, call: &CallExpression<'_>) {
        let Some(name) = sink_callee_name(&call.callee) else {
            return;
        };
        if ENCRYPT_API_NAMES.contains(&name) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4787",
                "Make sure using this encryption API is safe here.",
                call.span(),
            );
        }
    }
}
