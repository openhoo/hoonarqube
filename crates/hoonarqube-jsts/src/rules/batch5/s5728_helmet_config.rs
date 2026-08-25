use crate::rules::batch5::collectors::CSP_FETCH_DIRECTIVES;
use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::boolean_property;
use crate::rules::batch5::collectors::object_property;
use crate::rules::shared::argument_expression;
use crate::rules::shared::duplicated_key_name;
use crate::rules::shared::sink_callee_name;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_ast::ast::ObjectPropertyKind;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S5728`: helmet configurations disabling the CSP or its directives.
    pub(crate) fn check_helmet_config(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) != Some("helmet") {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(options) = unparenthesized(argument) else {
            return;
        };
        if boolean_property(options, "contentSecurityPolicy") == Some(false) {
            self.sink.emit_span(
                RuleScope::Both,
                "S5728",
                "Do not disable the Content Security Policy entirely.",
                call.span(),
            );
            return;
        }
        let Some(Expression::ObjectExpression(csp)) =
            object_property(options, "contentSecurityPolicy")
        else {
            return;
        };
        let Some(Expression::ObjectExpression(directives)) = object_property(csp, "directives")
        else {
            return;
        };
        for directive in &directives.properties {
            let ObjectPropertyKind::ObjectProperty(inner) = directive else {
                continue;
            };
            let disabled = duplicated_key_name(&inner.key)
                .is_some_and(|key| CSP_FETCH_DIRECTIVES.contains(&key))
                && match &inner.value {
                    Expression::BooleanLiteral(literal) => !literal.value,
                    Expression::ArrayExpression(items) => items.elements.is_empty(),
                    _ => false,
                };
            if disabled {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S5728",
                    "Do not disable this Content Security Policy directive.",
                    inner.key.span(),
                );
            }
        }
    }
}
