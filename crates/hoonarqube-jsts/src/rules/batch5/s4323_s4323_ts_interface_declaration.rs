use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::TSInterfaceDeclaration;
use oxc_ast::ast::TSSignature;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S4323` logic extracted from `visit_ts_interface_declaration`.
    pub(crate) fn check_s4323_ts_interface_declaration(&mut self, it: &TSInterfaceDeclaration<'_>) {
        self.check_single_call_signature(&it.body.body, it.span());

        self.check_overload_grouping(&it.body.body);

        if let [TSSignature::TSPropertySignature(_)] = it.body.body.as_slice() {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4323",
                "Prefer declaring this single-property interface as a type alias.",
                it.span(),
            );
        }
    }
}
