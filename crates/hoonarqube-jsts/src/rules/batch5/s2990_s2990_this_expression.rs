use super::collectors_hotspots::MiscCollector;
use crate::support::RuleScope;
use oxc_ast::ast::ThisExpression;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl MiscCollector<'_> {
    /// `S2990` logic extracted from `visit_this_expression`.
    pub(crate) fn check_s2990_this_expression(&mut self, it: &ThisExpression) {
        // `S2990`: `this` outside any function refers to the global object.
        if self.function_depth == 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S2990",
                "Remove this 'this'; it refers to the global object at module level.",
                it.span(),
            );
        }
    }
}
