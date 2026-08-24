use super::collectors::DuplicationCollector;
use crate::support::RuleScope;
use oxc_ast::ast::Declaration;
use oxc_ast::ast::ExportDeclaration;
use oxc_ast::ast::VariableDeclarationKind;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl DuplicationCollector<'_> {
    /// `S6861` logic extracted from `visit_export_declaration`.
    pub(crate) fn check_s6861_export_declaration(&mut self, it: &ExportDeclaration<'_>) {
        // `S6861`: mutable bindings must not be exported.
        if let Declaration::VariableDeclaration(variable) = &it.declaration
            && variable.kind != VariableDeclarationKind::Const
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6861",
                "Do not export mutable bindings.",
                it.span(),
            );
        }
    }
}
