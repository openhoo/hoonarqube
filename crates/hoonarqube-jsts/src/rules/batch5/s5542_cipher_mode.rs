use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::first_string_argument;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::rules::tier_c::walker::sink_callee_name;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S5542`: insecure cipher modes. ECB is always noncompliant. CBC is
    /// also within the documented scope (unauthenticated mode; the captured
    /// engine fires on AES-CBC controls regardless of IV and co-fires with
    /// `S5547` on weak CBC families), reported as a missing IV when none is
    /// supplied and as an insecure-mode finding otherwise.
    pub(crate) fn check_cipher_mode(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) != Some("createCipheriv") {
            return;
        }
        let Some(cipher) = first_string_argument(call) else {
            return;
        };
        let lowered = cipher.to_ascii_lowercase();
        if lowered.contains("ecb") {
            self.sink.emit_span(
                RuleScope::Both,
                "S5542",
                "Do not use the insecure ECB cipher mode.",
                call.span(),
            );
            return;
        }
        if !lowered.contains("cbc") {
            return;
        }
        let missing_iv = call
            .arguments
            .get(2)
            .and_then(argument_expression)
            .is_some_and(|expression| match unparenthesized(expression) {
                Expression::NullLiteral(_) => true,
                Expression::Identifier(identifier) => identifier.name == "undefined",
                _ => false,
            });
        if missing_iv {
            self.sink.emit_span(
                RuleScope::Both,
                "S5542",
                "Provide an initialization vector for this cipher.",
                call.span(),
            );
        } else {
            self.sink.emit_span(
                RuleScope::Both,
                "S5542",
                "Use a secure mode and padding scheme.",
                call.span(),
            );
        }
    }
}
