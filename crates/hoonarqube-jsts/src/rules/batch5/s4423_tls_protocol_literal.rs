use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::WEAK_TLS_PROTOCOLS;
use crate::support::RuleScope;
use oxc_ast::ast::StringLiteral;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S4423`: weak TLS protocol versions in string literals.
    pub(crate) fn check_tls_protocol_literal(&mut self, literal: &StringLiteral<'_>) {
        let lowered = literal.value.to_ascii_lowercase();
        if WEAK_TLS_PROTOCOLS.contains(&lowered.as_str()) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4423",
                "Make sure this weak TLS protocol version is safe here.",
                literal.span(),
            );
        }
    }
}
