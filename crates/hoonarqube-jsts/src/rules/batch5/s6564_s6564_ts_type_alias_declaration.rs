use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::TSType;
use oxc_ast::ast::TSTypeAliasDeclaration;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S6564` logic extracted from `visit_ts_type_alias_declaration`.
    pub(crate) fn check_s6564_ts_type_alias_declaration(
        &mut self,
        it: &TSTypeAliasDeclaration<'_>,
    ) {
        if let TSType::TSTypeReference(reference) = &it.type_annotation
            && reference.type_arguments.is_none()
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S6564",
                "Replace this alias with the type it references.",
                reference.span(),
            );
        }
    }
}
