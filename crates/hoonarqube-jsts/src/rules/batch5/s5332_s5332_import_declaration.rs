use super::collectors::{CLEARTEXT_MODULES, SecurityHotspotCollector};
use crate::support::RuleScope;
use oxc_ast::ast::ImportDeclaration;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl SecurityHotspotCollector<'_, '_> {
    /// `S5332` logic extracted from `visit_import_declaration`.
    pub(crate) fn check_s5332_import_declaration(&mut self, it: &ImportDeclaration<'_>) {
        self.check_xpath_module_import(it);

        self.check_socket_module_import(it);

        if CLEARTEXT_MODULES.contains(&it.source.value.as_str()) {
            self.sink.emit_span(
                RuleScope::Both,
                "S5332",
                "Use TLS-protected communication instead of this cleartext protocol.",
                it.span(),
            );
        }
    }
}
