use crate::rules::batch5::collectors::{
    SecurityFactory, SecurityHotspotCollector, SecurityValue, UNSAFE_REFERRER_POLICIES,
    boolean_property, object_property, string_property,
};
use crate::rules::shared::argument_expression;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::{CallExpression, Expression};
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// Helmet middleware and its named helpers (`S5730`, `S5734`, `S5736`,
    /// `S5739`). The callee is resolved to the imported module, not a
    /// spelling-only `helmet` match.
    pub(crate) fn check_helmet_config(&mut self, call: &CallExpression<'_>) {
        let origin = self.security_bindings.call_origin(call, call.span().start);
        let Some(options) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        match origin {
            crate::rules::batch5::collectors::SecurityOrigin::Factory(
                SecurityFactory::HelmetMiddleware,
            ) => {
                if option_bool(self, options, "noSniff", call.span().start) == Some(false) {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S5734",
                        "Enable the X-Content-Type-Options header with 'nosniff'.",
                        call.span(),
                    );
                }
            }
            crate::rules::batch5::collectors::SecurityOrigin::Factory(
                SecurityFactory::HelmetCsp,
            ) => {
                let Expression::ObjectExpression(options) = unparenthesized(options) else {
                    return;
                };
                let Some(Expression::ObjectExpression(directives)) =
                    object_property(options, "directives")
                else {
                    return;
                };
                if !block_all_mixed_content_enabled(directives) {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S5730",
                        "Enable 'block-all-mixed-content' in this Content Security Policy.",
                        call.span(),
                    );
                }
                if matches!(
                    object_property(directives, "frameAncestors"),
                    Some(value)
                        if matches!(unparenthesized(value), Expression::NullLiteral(_))
                ) {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S5732",
                        "Protect against clickjacking with 'frame-ancestors'.",
                        call.span(),
                    );
                }
            }
            crate::rules::batch5::collectors::SecurityOrigin::Factory(
                SecurityFactory::HelmetReferrerPolicy,
            ) => {
                if string_option(self, options, "policy", call.span().start)
                    .is_some_and(|policy| UNSAFE_REFERRER_POLICIES.contains(&policy.as_str()))
                {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S5736",
                        "Use a privacy-protecting 'Referrer-Policy' value.",
                        call.span(),
                    );
                }
            }
            crate::rules::batch5::collectors::SecurityOrigin::Factory(
                SecurityFactory::HelmetHsts,
            ) => {
                if number_option(self, options, "maxAge", call.span().start)
                    .is_some_and(|max_age| max_age < 31_536_000.0)
                {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S5739",
                        "Increase the Strict-Transport-Security max-age.",
                        call.span(),
                    );
                }
                if option_bool(self, options, "includeSubDomains", call.span().start) == Some(false)
                {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S5739",
                        "Include subdomains in the Strict-Transport-Security policy.",
                        call.span(),
                    );
                }
            }
            _ => {}
        }
    }
}

fn block_all_mixed_content_enabled(directives: &oxc_ast::ast::ObjectExpression<'_>) -> bool {
    match object_property(directives, "blockAllMixedContent").map(unparenthesized) {
        Some(Expression::BooleanLiteral(value)) => value.value,
        Some(Expression::ArrayExpression(array)) => array.elements.is_empty(),
        _ => false,
    }
}

fn option_bool(
    collector: &SecurityHotspotCollector<'_, '_>,
    expression: &Expression<'_>,
    key: &str,
    at: u32,
) -> Option<bool> {
    match unparenthesized(expression) {
        Expression::ObjectExpression(object) => boolean_property(object, key),
        _ => match collector
            .security_bindings
            .object_property(expression, key, at)?
        {
            SecurityValue::Boolean(value) => Some(value),
            _ => None,
        },
    }
}

fn string_option(
    collector: &SecurityHotspotCollector<'_, '_>,
    expression: &Expression<'_>,
    key: &str,
    at: u32,
) -> Option<String> {
    match unparenthesized(expression) {
        Expression::ObjectExpression(object) => string_property(object, key).map(str::to_owned),
        _ => match collector
            .security_bindings
            .object_property(expression, key, at)?
        {
            SecurityValue::String(value) => Some(value),
            _ => None,
        },
    }
}

fn number_option(
    collector: &SecurityHotspotCollector<'_, '_>,
    expression: &Expression<'_>,
    key: &str,
    at: u32,
) -> Option<f64> {
    match unparenthesized(expression) {
        Expression::ObjectExpression(object) => object_property(object, key).and_then(|value| {
            let Expression::NumericLiteral(value) = unparenthesized(value) else {
                return None;
            };
            Some(value.value)
        }),
        _ => match collector
            .security_bindings
            .object_property(expression, key, at)?
        {
            SecurityValue::Number(value) => Some(value),
            _ => None,
        },
    }
}
