use super::walker::TierCLiteralCollector;
use crate::engine::scope_model::LiteralKind;
use crate::engine::scope_model::literal_kind;
use crate::support::RuleScope;
use oxc_ast::ast::BinaryExpression;
use oxc_ast::ast::BinaryOperator;
use oxc_span::GetSpan;

impl TierCLiteralCollector<'_> {
    /// `S3785`: `in` used with a primitive-typed right-hand side.
    pub(crate) fn check_in_with_primitive(&mut self, expression: &BinaryExpression<'_>) {
        if expression.operator != BinaryOperator::In {
            return;
        }
        if matches!(
            literal_kind(&expression.right),
            Some(
                LiteralKind::String
                    | LiteralKind::Number
                    | LiteralKind::BigInt
                    | LiteralKind::Boolean
                    | LiteralKind::Null
                    | LiteralKind::Undefined
            )
        ) {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3785",
                "TypeError can be thrown as this operand might have primitive type.",
                expression.right.span(),
            );
        }
    }
}
