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
                TSType::TSAnyKeyword(_) | TSType::TSUnknownKeyword(_)
            )
        {
            let constraint_name = if matches!(constraint, TSType::TSAnyKeyword(_)) {
                "any"
            } else {
                "unknown"
            };
            let message = format!(
                "Constraining the generic type `{}` to `{constraint_name}` does nothing and is unnecessary.",
                it.name.name
            );
            self.sink
                .emit_span(RuleScope::TsOnly, "S6569", &message, it.span());
        }
    }
}
