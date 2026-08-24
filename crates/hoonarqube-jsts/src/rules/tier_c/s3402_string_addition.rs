use super::walker::TierCLiteralCollector;
use crate::engine::scope_model::LiteralKind;
use crate::engine::scope_model::literal_kind;
use crate::support::RuleScope;
use oxc_ast::ast::BinaryExpression;
use oxc_ast::ast::BinaryOperator;
use oxc_span::GetSpan;

impl TierCLiteralCollector<'_> {
    /// `S3402`: `'str' + <non-string literal>` operand pairs.
    pub(crate) fn check_string_addition(&mut self, expression: &BinaryExpression<'_>) {
        if expression.operator != BinaryOperator::Addition {
            return;
        }
        let mixed = matches!(
            (
                literal_kind(&expression.left),
                literal_kind(&expression.right),
            ),
            (Some(LiteralKind::String), Some(kind)) | (Some(kind), Some(LiteralKind::String))
                if kind != LiteralKind::String
        );
        if mixed {
            self.sink.emit_span(
                RuleScope::Both,
                "S3402",
                "Convert this non-string operand explicitly instead of relying on '+'.",
                expression.span(),
            );
        }
    }
}
