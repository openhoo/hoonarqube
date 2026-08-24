use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::AwaitExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S4326` logic extracted from `visit_await_expression`.
    pub(crate) fn check_s4326_await_expression(&mut self, it: &AwaitExpression<'_>) {
        if let Expression::AwaitExpression(inner) = unparenthesized(&it.argument) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4326",
                "Remove this nested await; awaiting an awaited value is redundant.",
                inner.span(),
            );
        }
    }
}
