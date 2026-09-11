use crate::rules::batch5::collectors::{
    SecurityHotspotCollector, SecurityModule, SecurityValue, object_property,
};
use crate::rules::shared::argument_expression;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::{CallExpression, Expression};
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S2755`: XML parser configurations allowing entity expansion.
    pub(crate) fn check_xml_parser(&mut self, call: &CallExpression<'_>) {
        let is_parser = self.security_bindings.is_module_member(
            &call.callee,
            SecurityModule::LibXmlJs,
            "parseXmlString",
            call.span().start,
        ) || self.security_bindings.is_module_member(
            &call.callee,
            SecurityModule::LibXmlJs,
            "parseXml",
            call.span().start,
        );
        if !is_parser {
            return;
        }
        let Some(options) = call.arguments.get(1).and_then(argument_expression) else {
            return;
        };
        let noent = option_bool(self, options, "noent", call.span().start);
        let noxxe = option_bool(self, options, "noxxe", call.span().start);
        if noent == Some(true) || noxxe == Some(false) {
            self.sink.emit_span(
                RuleScope::Both,
                "S2755",
                "Disable access to external entities in XML parsing.",
                options.span(),
            );
        }
    }
}

fn option_bool(
    collector: &SecurityHotspotCollector<'_, '_>,
    expression: &Expression<'_>,
    key: &str,
    at: u32,
) -> Option<bool> {
    match unparenthesized(expression) {
        Expression::ObjectExpression(object) => match object_property(object, key)? {
            Expression::BooleanLiteral(literal) => Some(literal.value),
            _ => None,
        },
        _ => match collector
            .security_bindings
            .object_property(expression, key, at)?
        {
            SecurityValue::Boolean(value) => Some(value),
            _ => None,
        },
    }
}
