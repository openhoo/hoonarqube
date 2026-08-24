use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::TSType;
use oxc_ast::ast::TSTypeParameter;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S6569` logic extracted from `visit_ts_type_parameter`.
    pub(crate) fn check_s6569_ts_type_parameter(&mut self, it: &TSTypeParameter<'_>) {
        if let Some(constraint) = &it.constraint
            && matches!(
                constraint,
                TSType::TSAnyKeyword(_) | TSType::TSUnknownKeyword(_) | TSType::TSObjectKeyword(_)
            )
        {
            self.sink.emit_span(
                RuleScope::TsOnly,
                "S6569",
                "This constraint does not meaningfully restrict the type parameter; remove it.",
                constraint.span(),
            );
        }
    }
}
