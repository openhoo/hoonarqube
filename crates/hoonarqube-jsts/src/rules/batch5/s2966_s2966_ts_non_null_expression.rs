use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::TSNonNullExpression;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S2966` logic extracted from `visit_ts_non_null_expression`.
    pub(crate) fn check_s2966_ts_non_null_expression(&mut self, it: &TSNonNullExpression<'_>) {
        self.sink.emit_span(
            RuleScope::TsOnly,
            "S2966",
            "Remove this non-null assertion; it can hide null or undefined values.",
            it.span(),
        );
    }
}
