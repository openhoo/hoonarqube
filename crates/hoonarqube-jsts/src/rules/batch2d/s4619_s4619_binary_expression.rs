use super::collectors::PromiseFlowCollector;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::BinaryExpression;
use oxc_ast::ast::BinaryOperator;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl PromiseFlowCollector<'_> {
    /// `S4619` logic extracted from `visit_binary_expression`.
    pub(crate) fn check_s4619_binary_expression(&mut self, it: &BinaryExpression<'_>) {
        if it.operator == BinaryOperator::In {
            let flagged = match unparenthesized(&it.right) {
                Expression::ArrayExpression(_) => true,
                Expression::Identifier(identifier) => {
                    self.array_bindings.contains(identifier.name.as_str())
                }
                _ => false,
            };
            if flagged {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S4619",
                    "Use \"indexOf\" or \"includes\" (available from ES2016) instead.",
                    it.span(),
                );
            }
        }
    }
}
