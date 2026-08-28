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
    /// `S2755`: XML parser configurations allowing entity expansion.
    pub(crate) fn check_xml_parser(&mut self, call: &CallExpression<'_>) {
        if !matches!(
            sink_callee_name(&call.callee),
            Some("parseXml" | "parseXmlString")
        ) {
            return;
        }
        let Some(options) = call.arguments.get(1).and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(object) = unparenthesized(options) else {
            return;
        };
        let expands = boolean_property(object, "noent") == Some(true);
        if expands || object_property(object, "noxxe").is_none() {
            let anchor = object.properties.iter().find_map(|property| {
                let ObjectPropertyKind::ObjectProperty(inner) = property else {
                    return None;
                };
                (duplicated_key_name(&inner.key) == Some("noent")).then(|| inner.span())
            });
            self.sink.emit_span(
                RuleScope::Both,
                "S2755",
                "Disable access to external entities in XML parsing.",
                anchor.unwrap_or_else(|| options.span()),
            );
        }
    }
}
