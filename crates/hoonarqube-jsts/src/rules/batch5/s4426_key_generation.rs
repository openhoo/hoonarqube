use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::WEAK_EC_CURVES;
use crate::rules::batch5::collectors::first_string_argument;
use crate::rules::batch5::collectors::number_property;
use crate::rules::batch5::collectors::string_property;
use crate::rules::shared::argument_expression;
use crate::rules::shared::sink_callee_name;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S4426`: key generation over weak curves or short moduli.
    pub(crate) fn check_key_generation(&mut self, call: &CallExpression<'_>) {
        let Some(name) = sink_callee_name(&call.callee) else {
            return;
        };
        if name == "createECDH" {
            let Some(curve) = first_string_argument(call) else {
                return;
            };
            if WEAK_EC_CURVES.contains(&curve) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S4426",
                    "Make sure generating keys with this weak curve is safe here.",
                    call.span(),
                );
            }
            return;
        }
        if !matches!(name, "generateKeyPair" | "generateKeyPairSync") {
            return;
        }
        let Some(kind) = first_string_argument(call) else {
            return;
        };
        if !matches!(kind, "rsa" | "dsa" | "ec" | "ed25519") {
            return;
        }
        let Some(options) = call.arguments.get(1).and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(object) = unparenthesized(options) else {
            return;
        };
        let weak_modulus =
            number_property(object, "modulusLength").is_some_and(|bits| bits < 2048.0);
        let weak_curve = string_property(object, "namedCurve")
            .is_some_and(|curve| WEAK_EC_CURVES.contains(&curve));
        if weak_modulus || weak_curve {
            self.sink.emit_span(
                RuleScope::Both,
                "S4426",
                "Make sure generating keys with these weak parameters is safe here.",
                call.span(),
            );
        }
    }
}
