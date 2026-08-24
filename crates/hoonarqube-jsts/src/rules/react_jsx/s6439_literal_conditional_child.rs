use super::walker::ReactCollector;
use crate::support::RuleScope;
use oxc_ast::ast::Expression;
use oxc_ast::ast::JSXExpressionContainer;
use oxc_ast::ast::LogicalOperator;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6439`: `{literal && <element/>}` children render the literal when
    /// the condition is falsy-but-present.
    pub(crate) fn check_literal_conditional_child(
        &mut self,
        container: &JSXExpressionContainer<'_>,
    ) {
        if self.jsx_child_depth == 0 {
            return;
        }
        let Some(Expression::LogicalExpression(logical)) = container.expression.as_expression()
        else {
            return;
        };
        if logical.operator != LogicalOperator::And
            || !matches!(
                logical.left,
                Expression::NumericLiteral(_)
                    | Expression::StringLiteral(_)
                    | Expression::BigIntLiteral(_)
            )
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6439",
            "This branch renders a literal; guard it with an explicit boolean condition.",
            container.span(),
        );
    }
}
