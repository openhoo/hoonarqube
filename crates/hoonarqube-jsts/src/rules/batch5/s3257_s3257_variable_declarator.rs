use super::collectors::{TsTypeCollector, type_is_primitive_keyword};
use crate::support::RuleScope;
use oxc_ast::ast::VariableDeclarator;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S3257` logic extracted from `visit_variable_declarator`.
    pub(crate) fn check_s3257_variable_declarator(&mut self, it: &VariableDeclarator<'_>) {
        if let Some(annotation) = &it.type_annotation
            && type_is_primitive_keyword(&annotation.type_annotation)
            && it.init.is_some()
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S3257",
                "Remove this redundant type annotation; the initializer already provides the type.",
                annotation.span(),
            );
        }
    }
}
