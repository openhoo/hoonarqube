use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use oxc_ast::ast::TSAnyKeyword;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S4204` logic extracted from `visit_ts_any_keyword`.
    pub(crate) fn check_s4204_ts_any_keyword(&mut self, it: &TSAnyKeyword) {
        self.sink.emit_span(
            RuleScope::TsOnly,
            "S4204",
            "Unexpected any. Specify a different type.",
            it.span(),
        );
    }
}
