use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::WEAK_CIPHER_FAMILIES;
use crate::rules::batch5::collectors::first_string_argument;
use crate::rules::tier_c::walker::sink_callee_name;
use crate::support::RuleScope;
use oxc_ast::ast::CallExpression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S5547`: broken cipher families in `createCipheriv` calls.
    pub(crate) fn check_weak_cipher(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) != Some("createCipheriv") {
            return;
        }
        let Some(cipher) = first_string_argument(call) else {
            return;
        };
        let lowered = cipher.to_ascii_lowercase();
        let family = lowered.split('-').next().unwrap_or_default();
        if WEAK_CIPHER_FAMILIES.contains(&family) {
            self.sink.emit_span(
                RuleScope::Both,
                "S5547",
                &format!("Make sure encrypting with '{cipher}' is safe here."),
                call.span(),
            );
        }
    }
}
