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
        let composite = literal_kind(&expression.left).is_some_and(kind_is_composite)
            || literal_kind(&expression.right).is_some_and(kind_is_composite);
        if composite {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3758",
                "This comparison coerces the operand to '[object Object]'.",
                expression.span(),
            );
        }
    }
}
