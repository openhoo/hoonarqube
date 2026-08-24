use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::FormalParameter;
use oxc_ast::ast::TSType;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S4798` logic extracted from `visit_formal_parameter`.
    pub(crate) fn check_s4798_formal_parameter(&mut self, it: &FormalParameter<'_>) {
        if let Some(annotation) = &it.type_annotation
            && it.optional
            && it.initializer.is_none()
            && matches!(annotation.type_annotation, TSType::TSBooleanKeyword(_))
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4798",
                "Provide a default value for this optional boolean parameter.",
                it.span(),
            );
        }
    }
}
