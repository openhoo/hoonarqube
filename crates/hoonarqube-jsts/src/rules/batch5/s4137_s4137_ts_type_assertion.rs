use super::collectors::TsTypeCollector;
use crate::support::{RuleScope, source_slice};
use oxc_ast::ast::TSTypeAssertion;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S4137` logic extracted from `visit_ts_type_assertion`.
    pub(crate) fn check_s4137_ts_type_assertion(&mut self, it: &TSTypeAssertion<'_>) {
        let asserted_type = source_slice(self.source, it.type_annotation.span()).trim();
        self.sink.emit_span(
            RuleScope::TsOnly,
            "S4137",
            &format!("Use 'as {asserted_type}' instead of '<{asserted_type}>'."),
            it.span(),
        );
    }
}
