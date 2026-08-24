use crate::rules::batch5::collectors::CLEARTEXT_MODULES;
use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::first_string_argument;
use crate::rules::tier_c::walker::sink_callee_name;
use crate::support::RuleScope;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::StringLiteral;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S5332`: cleartext modules pulled in through `require`.
    pub(crate) fn check_cleartext_require(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) != Some("require") {
            return;
        }
        if let Some(module) = first_string_argument(call)
            && CLEARTEXT_MODULES.contains(&module)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S5332",
                "Use TLS-protected communication instead of this cleartext protocol.",
                call.span(),
            );
        }
    }

    /// `S5332`: cleartext `http://` / `ws://` URLs in string literals.
    pub(crate) fn check_cleartext_scheme(&mut self, literal: &StringLiteral<'_>) {
        let lowered = literal.value.to_ascii_lowercase();
        if lowered.starts_with("http://") || lowered.starts_with("ws://") {
            self.sink.emit_span(
                RuleScope::Both,
                "S5332",
                "Use TLS-protected communication instead of this cleartext protocol.",
                literal.span(),
            );
        }
    }
}
