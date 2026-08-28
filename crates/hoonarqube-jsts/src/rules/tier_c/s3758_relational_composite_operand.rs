use super::walker::TierCLiteralCollector;
use crate::engine::scope_model::kind_is_composite;
use crate::engine::scope_model::literal_kind;
use crate::support::RuleScope;
use oxc_ast::ast::BinaryExpression;
use oxc_ast::ast::BinaryOperator;
use oxc_span::GetSpan;

impl TierCLiteralCollector<'_> {
    /// `S3758`: relational comparisons over composite literals.
    pub(crate) fn check_relational_composite_operand(&mut self, expression: &BinaryExpression<'_>) {
        if !matches!(
            expression.operator,
            BinaryOperator::LessThan
                | BinaryOperator::GreaterThan
                | BinaryOperator::LessEqualThan
                | BinaryOperator::GreaterEqualThan
        ) {
            return;
        }
        for operand in [&expression.left, &expression.right] {
            if !literal_kind(operand).is_some_and(kind_is_composite) {
                continue;
            }
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3758",
                "Re-evaluate the data flow; this operand of a numeric comparison could be of type {}.",
                operand.span(),
            );
        }
    }
}
