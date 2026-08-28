use super::walker::TierCLiteralCollector;
use crate::engine::scope_model::literal_kind;
use crate::support::RuleScope;
use oxc_ast::ast::BinaryExpression;
use oxc_ast::ast::BinaryOperator;
use oxc_span::GetSpan;

impl TierCLiteralCollector<'_> {
    /// `S3403`: `===`/`!==` between literals of different categories.
    pub(crate) fn check_dissimilar_strict_equality(&mut self, expression: &BinaryExpression<'_>) {
        if !matches!(
            expression.operator,
            BinaryOperator::StrictEquality | BinaryOperator::StrictInequality
        ) {
            return;
        }
        let (Some(left), Some(right)) = (
            literal_kind(&expression.left),
            literal_kind(&expression.right),
        ) else {
            return;
        };
        if left != right {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3403",
                if expression.operator == BinaryOperator::StrictEquality {
                    "Remove this \"===\" check; it will always be false. Did you mean to use \"==\"?"
                } else {
                    "Remove this \"!==\" check; it will always be true. Did you mean to use \"!=\"?"
                },
                oxc_span::Span::new(
                    expression.left.span().end.saturating_add(1),
                    expression.right.span().start.saturating_sub(1),
                ),
            );
        }
    }
}
