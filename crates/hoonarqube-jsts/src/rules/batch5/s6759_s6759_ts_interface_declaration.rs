use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::TSInterfaceDeclaration;
use oxc_ast::ast::TSSignature;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S6759` logic extracted from `visit_ts_interface_declaration`.
    pub(crate) fn check_s6759_ts_interface_declaration(&mut self, it: &TSInterfaceDeclaration<'_>) {
        if it.id.name.contains("Props") {
            for member in &it.body.body {
                if let TSSignature::TSPropertySignature(property) = member
                    && !property.readonly
                {
                    self.sink.emit_span(
                        RuleScope::TsOnly,
                        "S6759",
                        "Add the readonly modifier to this property.",
                        property.span(),
                    );
                }
            }
        }
    }
}
