use super::walker::ReactCollector;
use crate::support::RuleScope;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl ReactCollector<'_> {
    /// `S6757` logic extracted from `visit_this_expression`.
    pub(crate) fn check_s6757_this_expression(&mut self, it: &oxc_ast::ast::ThisExpression) {
        if self.method_guard == 0
            && self.class_depth == 0
            && self.component_stack.last() == Some(&true)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6757",
                "'this' is undefined inside a functional component; capture the needed values instead.",
                it.span(),
            );
        }
    }
}
