use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::TSPropertySignature;
use oxc_ast::ast::TSType;
use oxc_span::GetSpan;

/// `S4782` helper: does the type union contain the `undefined` keyword?
fn union_contains_undefined(ts_type: &TSType<'_>) -> bool {
    match ts_type {
        TSType::TSUnionType(union) => union
            .types
            .iter()
            .any(|member| matches!(member, TSType::TSUndefinedKeyword(_))),
        _ => false,
    }
}

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S4782` logic extracted from `visit_ts_property_signature`.
    pub(crate) fn check_s4782_ts_property_signature(&mut self, it: &TSPropertySignature<'_>) {
        if let Some(annotation) = &it.type_annotation
            && it.optional
            && union_contains_undefined(&annotation.type_annotation)
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4782",
                "Remove the undefined member from this union; the property is already optional.",
                it.span(),
            );
        }
    }
}
