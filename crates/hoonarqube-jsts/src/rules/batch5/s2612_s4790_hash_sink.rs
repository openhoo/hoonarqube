use crate::rules::batch5::collectors::{
    SecurityHotspotCollector, SecurityModule, WEAK_HASH_FAMILY, first_string_argument,
};
use crate::rules::shared::argument_expression;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::{CallExpression, Expression};
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S2612` owns world-accessible file permissions; `S4790` owns weak hashes.
    pub(crate) fn check_hash_sink(&mut self, call: &CallExpression<'_>) {
        if self.security_bindings.is_module_member(
            &call.callee,
            SecurityModule::Crypto,
            "createHash",
            call.span().start,
        ) {
            let Some(algorithm) = first_string_argument(call) else {
                return;
            };
            let lowered = algorithm.to_ascii_lowercase();
            if WEAK_HASH_FAMILY.contains(&lowered.as_str()) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S4790",
                    "Make sure this weak hash algorithm is not used in a sensitive context here.",
                    call.callee.span(),
                );
            }
            return;
        }

        let is_chmod = self.security_bindings.is_module_member(
            &call.callee,
            SecurityModule::Fs,
            "chmod",
            call.span().start,
        ) || self.security_bindings.is_module_member(
            &call.callee,
            SecurityModule::Fs,
            "chmodSync",
            call.span().start,
        );
        if !is_chmod {
            return;
        }
        let Some(Expression::NumericLiteral(mode)) = call
            .arguments
            .get(1)
            .and_then(argument_expression)
            .map(unparenthesized)
        else {
            return;
        };
        if has_world_permissions(mode.value) {
            self.sink.emit_span(
                RuleScope::Both,
                "S2612",
                "Make sure this permission is safe.",
                mode.span(),
            );
        }
    }
}

fn has_world_permissions(mode: f64) -> bool {
    if mode.is_nan() || mode <= 0.0 {
        return false;
    }
    if mode >= f64::from(u32::MAX) {
        return true;
    }
    mode.trunc().rem_euclid(8.0) > 0.0
}
