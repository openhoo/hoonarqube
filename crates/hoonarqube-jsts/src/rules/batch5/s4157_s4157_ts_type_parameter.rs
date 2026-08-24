use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use crate::support::source_slice;
use oxc_ast::ast::TSTypeParameter;
use oxc_span::{GetSpan, Span};

impl TsTypeCollector<'_, '_> {
    fn source_slice_eq(&self, left: Span, right: Span) -> bool {
        source_slice(self.source, left) == source_slice(self.source, right)
    }
}

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S4157` logic extracted from `visit_ts_type_parameter`.
    pub(crate) fn check_s4157_ts_type_parameter(&mut self, it: &TSTypeParameter<'_>) {
        if let (Some(constraint), Some(default)) = (&it.constraint, &it.default)
            && self.source_slice_eq(constraint.span(), default.span())
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S4157",
                "Remove this redundant type parameter default; it repeats the constraint.",
                default.span(),
            );
        }
    }
}
