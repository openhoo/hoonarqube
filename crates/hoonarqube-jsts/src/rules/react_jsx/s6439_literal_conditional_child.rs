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
            "Convert the conditional to a boolean to avoid leaked value",
            logical.left.span(),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6439_flags_numeric_guard_as_jsx_child() {
        let findings = jsx_keys("const el = <div>{0 && <b></b>}</div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6439"), 1);
    }

    #[test]
    fn s6439_allows_boolean_guard() {
        let findings = jsx_keys("let ready = true;\nconst el = <div>{ready && <b></b>}</div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6439"), 0);
    }

    #[test]
    fn s6439_ignores_attribute_position_guards() {
        let findings = jsx_keys("const el = <div title={5 && <b></b>}></div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6439"), 0);
    }
}
