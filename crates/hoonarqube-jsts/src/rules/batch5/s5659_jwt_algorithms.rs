use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::WEAK_JWT_ALGORITHMS;
use crate::rules::batch5::collectors::string_property;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::RuleScope;
use crate::support::expression_root_name;
use crate::support::unparenthesized;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S5659`: weak JWT signing or verification algorithms.
    pub(crate) fn check_jwt_algorithms(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        if !(member.property.name == "sign" || member.property.name == "verify")
            || expression_root_name(&member.object) != Some("jwt")
        {
            return;
        }
        let weak = call.arguments.iter().any(|argument| {
            let Some(expression) = argument_expression(argument) else {
                return false;
            };
            match unparenthesized(expression) {
                Expression::StringLiteral(literal) => {
                    WEAK_JWT_ALGORITHMS.contains(&literal.value.as_str())
                }
                Expression::ObjectExpression(object) => string_property(object, "algorithm")
                    .is_some_and(|algorithm| WEAK_JWT_ALGORITHMS.contains(&algorithm)),
                _ => false,
            }
        });
        if weak {
            self.sink.emit_span(
                RuleScope::Both,
                "S5659",
                "Sign and verify JWTs with strong algorithms only.",
                call.span(),
            );
        }
    }
}
