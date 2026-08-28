use super::walker::TierCLiteralCollector;
use crate::engine::scope_model::LiteralKind;
use crate::engine::scope_model::kind_is_numeric;
use crate::engine::scope_model::literal_kind;
use crate::support::RuleScope;
use oxc_ast::ast::BinaryExpression;
use oxc_ast::ast::BinaryOperator;
use oxc_span::GetSpan;

impl TierCLiteralCollector<'_> {
    /// `S3760`: arithmetic operators over non-numeric operands.
    pub(crate) fn check_arithmetic_non_number(&mut self, expression: &BinaryExpression<'_>) {
        let (Some(left), Some(right)) = (
            literal_kind(&expression.left),
            literal_kind(&expression.right),
        ) else {
            return;
        };
        if kind_is_numeric(left) && kind_is_numeric(right) {
            return;
        }
        let flagged = match expression.operator {
            // `'str' + x` pairs are `S3402`'s territory; plain numeric
            // additions are fine. Anything else adding up is coercion.
            BinaryOperator::Addition => {
                left != LiteralKind::String
                    && right != LiteralKind::String
                    && (!kind_is_numeric(left) || !kind_is_numeric(right))
            }
            BinaryOperator::Subtraction
            | BinaryOperator::Multiplication
            | BinaryOperator::Division
            | BinaryOperator::Remainder
            | BinaryOperator::Exponential => true,
            _ => false,
        };
        if flagged {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3760",
                "Convert the operands of this operation into numbers.",
                expression.span(),
            );
        }
    }
}
