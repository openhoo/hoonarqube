use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::WEAK_HASH_ALGORITHMS;
use crate::rules::batch5::collectors::WEAK_HASH_FAMILY;
use crate::rules::batch5::collectors::first_string_argument;
use crate::rules::tier_c::walker::sink_callee_name;
use crate::support::RuleScope;
use oxc_ast::ast::CallExpression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S2612` and `S4790`: weak algorithms in `createHash` calls.
    pub(crate) fn check_hash_sink(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) != Some("createHash") {
            return;
        }
        let Some(algorithm) = first_string_argument(call) else {
            return;
        };
        let lowered = algorithm.to_ascii_lowercase();
        if WEAK_HASH_ALGORITHMS.contains(&lowered.as_str()) {
            self.sink.emit_span(
                RuleScope::Both,
                "S2612",
                &format!("Make sure hashing with '{lowered}' is safe here."),
                call.span(),
            );
        }
        if WEAK_HASH_FAMILY.contains(&lowered.as_str()) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4790",
                &format!("Use a stronger hash algorithm than '{lowered}'."),
                call.span(),
            );
        }
    }
}
