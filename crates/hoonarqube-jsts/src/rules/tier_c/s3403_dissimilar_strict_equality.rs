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
            let operator = if expression.operator == BinaryOperator::StrictEquality {
                "==="
            } else {
                "!=="
            };
            let start = expression.left.span().end as usize;
            let end = expression.right.span().start as usize;
            let operator_span = self
                .source
                .get(start..end)
                .and_then(|gap| gap.find(operator))
                .map_or_else(
                    || expression.span(),
                    |offset| {
                        let start = crate::support::to_u32(start + offset);
                        oxc_span::Span::new(start, start.saturating_add(3))
                    },
                );
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S3403",
                if expression.operator == BinaryOperator::StrictEquality {
                    "Remove this \"===\" check; it will always be false. Did you mean to use \"==\"?"
                } else {
                    "Remove this \"!==\" check; it will always be true. Did you mean to use \"!=\"?"
                },
                operator_span,
            );
        }
    }
}
