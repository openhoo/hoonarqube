use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::object_property;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::rules::tier_c::walker::sink_callee_name;
use crate::support::RuleScope;
use crate::support::constructor_name;
use crate::support::unparenthesized;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_ast::ast::NewExpression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S2598` (call form): upload handlers without a `limits` object.
    pub(crate) fn check_upload_limits(&mut self, call: &CallExpression<'_>) {
        if !matches!(sink_callee_name(&call.callee), Some("multer" | "busboy")) {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(object) = unparenthesized(argument) else {
            return;
        };
        if object_property(object, "limits").is_none() {
            self.sink.emit_span(
                RuleScope::Both,
                "S2598",
                "Limit the size of uploaded files.",
                call.span(),
            );
        }
    }

    /// `S2598` (constructor form): `new Busboy({...})` without limits.
    pub(crate) fn check_new_upload(&mut self, new: &NewExpression<'_>) {
        if constructor_name(new) != Some("Busboy") {
            return;
        }
        let Some(argument) = new.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(object) = unparenthesized(argument) else {
            return;
        };
        if object_property(object, "limits").is_none() {
            self.sink.emit_span(
                RuleScope::Both,
                "S2598",
                "Limit the size of uploaded files.",
                new.span(),
            );
        }
    }
}
