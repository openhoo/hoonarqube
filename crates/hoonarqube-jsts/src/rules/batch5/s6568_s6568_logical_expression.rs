use super::collectors::TsTypeCollector;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::Expression;
use oxc_ast::ast::LogicalExpression;
use oxc_ast::ast::LogicalOperator;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl TsTypeCollector<'_, '_> {
    /// `S6568` logic extracted from `visit_logical_expression`.
    pub(crate) fn check_s6568_logical_expression(&mut self, it: &LogicalExpression<'_>) {
        if matches!(it.operator, LogicalOperator::Coalesce | LogicalOperator::Or) {
            for operand in [&it.left, &it.right] {
                if let Expression::TSNonNullExpression(assertion) = unparenthesized(operand) {
                    self.sink.emit_span(
                        RuleScope::TsOnly,
                        "S6568",
                        "Remove this unnecessary non-null assertion; the guard already handles null and undefined.",
                        assertion.span(),
                    );
                }
            }
        }
    }
}
