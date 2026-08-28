use super::collectors::{TsTypeCollector, type_is_primitive_keyword};
use crate::support::{RuleScope, source_slice};
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
            let inferred_type = source_slice(self.source, annotation.type_annotation.span());
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S3257",
                &format!(
                    "Type {inferred_type} trivially inferred from a {inferred_type} literal, remove type annotation."
                ),
                oxc_span::Span::new(
                    it.id.span().start,
                    it.init
                        .as_ref()
                        .map_or(annotation.span().end, |init| init.span().end),
                ),
            );
        }
    }
}
