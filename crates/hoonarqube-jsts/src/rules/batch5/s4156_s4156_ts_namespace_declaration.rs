use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::TSNamespaceDeclaration;
use oxc_ast::ast::TSNamespaceDeclarationKind;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S4156` logic extracted from `visit_ts_namespace_declaration`.
    pub(crate) fn check_s4156_ts_namespace_declaration(&mut self, it: &TSNamespaceDeclaration<'_>) {
        if it.kind == TSNamespaceDeclarationKind::Module {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4156",
                "Prefer the namespace keyword over module for these declarations.",
                it.span(),
            );
        }
    }
}
