use super::collectors::PromiseFlowCollector;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::RuleScope;
use crate::support::identifier_name;
use crate::support::member_rooted_at;
use crate::support::static_property_name;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

pub(crate) fn is_plain_literal(expression: &Expression<'_>) -> bool {
    matches!(
        expression,
        Expression::StringLiteral(_)
            | Expression::NumericLiteral(_)
            | Expression::BooleanLiteral(_)
            | Expression::NullLiteral(_)
            | Expression::BigIntLiteral(_)
            | Expression::TemplateLiteral(_)
    )
}

// Generated per-rule checks (moved out of traversal overrides).
impl PromiseFlowCollector<'_> {
    /// `S6671` logic extracted from `visit_call_expression`.
    pub(crate) fn check_s6671_call_expression(&mut self, it: &CallExpression<'_>) {
        // `S6671`: rejecting with a plain literal value.
        let rejects = identifier_name(&it.callee) == Some("reject")
            || it.callee.as_member_expression().is_some_and(|member| {
                static_property_name(member) == Some("reject")
                    && member_rooted_at(member, "Promise")
            });

        if rejects
            && let Some(argument) = it.arguments.first().and_then(argument_expression)
            && is_plain_literal(argument)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6671",
                "Reject this promise with an \"Error\" object instead of a literal value.",
                it.span(),
            );
        }
    }
}
