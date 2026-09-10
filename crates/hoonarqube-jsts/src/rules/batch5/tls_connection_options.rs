use crate::rules::batch5::collectors::{SecurityHotspotCollector, SecurityModule, SecurityValue};
use crate::rules::shared::argument_expression;
use crate::support::RuleScope;
use oxc_ast::ast::CallExpression;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S4830` and `S5527`: TLS certificate and hostname verification options.
    ///
    /// Both live and pinned upstream controls miss concise arrows that return
    /// unshadowed `undefined`; native coverage intentionally closes that gap.
    pub(crate) fn check_tls_options(&mut self, call: &CallExpression<'_>) {
        let at = call.span().start;
        let is_tls_request = self.security_bindings.is_module_member(
            &call.callee,
            SecurityModule::Https,
            "request",
            at,
        ) || self.security_bindings.is_module_member(
            &call.callee,
            SecurityModule::Tls,
            "connect",
            at,
        );
        if !is_tls_request {
            return;
        }
        let Some(options) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let certificate_validation_disabled =
            self.security_bindings
                .object_property(options, "rejectUnauthorized", at)
                == Some(SecurityValue::Boolean(false));
        if certificate_validation_disabled {
            self.sink.emit_span(
                RuleScope::Both,
                "S4830",
                "Do not disable TLS certificate validation.",
                call.span(),
            );
        }
        let hostname_validation_disabled = self
            .security_bindings
            .object_property_is_inert_function(options, "checkServerIdentity", at);
        if certificate_validation_disabled || hostname_validation_disabled {
            self.sink.emit_span(
                RuleScope::Both,
                "S5527",
                "Enable server hostname verification on this SSL/TLS connection.",
                call.callee.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{count_key, js_keys, ts_keys};

    #[test]
    fn concise_undefined_hostname_callbacks_are_reported_in_typescript() {
        let source = "import * as https from 'node:https';\n\
const request = https.request({ hostname: 'www.example.com', port: 443, checkServerIdentity: (_hostname, _certificate) => undefined, secureProtocol: 'TLSv1_2_method' }, (response) => {\n\
  response.resume();\n\
});\n\
request.end();\n";
        assert_eq!(count_key(&ts_keys(source), "typescript:S5527"), 1);
    }

    #[test]
    fn empty_callbacks_remain_reported_and_real_callbacks_remain_clean() {
        let empty = "const https = require('node:https');\nhttps.request({ checkServerIdentity: function() {} }, () => {});\n";
        assert_eq!(count_key(&js_keys(empty), "javascript:S5527"), 1);

        let validating = "const https = require('node:https');\nhttps.request({ checkServerIdentity: (_hostname, _certificate) => new Error('mismatch') }, () => {});\n";
        assert_eq!(count_key(&js_keys(validating), "javascript:S5527"), 0);

        let throwing = "const https = require('node:https');\nhttps.request({ checkServerIdentity: () => { throw new Error('mismatch'); } }, () => {});\n";
        assert_eq!(count_key(&js_keys(throwing), "javascript:S5527"), 0);
    }

    #[test]
    fn shadowed_undefined_is_not_mistaken_for_an_inert_callback() {
        let source = "const https = require('https');\nfunction configure(undefined) {\n  https.request({ checkServerIdentity: (_hostname, _certificate) => undefined }, () => {});\n}\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S5527"), 0);
    }

    #[test]
    fn bound_and_mutated_hostname_options_use_current_values() {
        let source = "const https = require('https');\n\
const options = { checkServerIdentity: (_hostname, _certificate) => undefined };\n\
https.request(options, () => {});\n\
const changed = { checkServerIdentity: (_hostname, _certificate) => undefined };\n\
changed.checkServerIdentity = (_hostname, _certificate) => new Error('mismatch');\n\
https.request(changed, () => {});\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S5527"), 1);
    }

    #[test]
    fn computed_dynamic_delete_and_update_writes_invalidate_current_options() {
        let source = "const https = require('https');\n\
const before = { rejectUnauthorized: false };\n\
https.request(before, () => {});\n\
const computed = { rejectUnauthorized: false };\n\
computed['rejectUnauthorized'] = true;\n\
https.request(computed, () => {});\n\
const dynamic = { rejectUnauthorized: false };\n\
const key = process.env.TLS_OPTION;\n\
dynamic[key] = true;\n\
https.request(dynamic, () => {});\n\
const deleted = { rejectUnauthorized: false };\n\
delete deleted.rejectUnauthorized;\n\
https.request(deleted, () => {});\n\
const updated = { rejectUnauthorized: false };\n\
updated.rejectUnauthorized++;\n\
https.request(updated, () => {});\n\
const unrelated = { rejectUnauthorized: false };\n\
unrelated.other = true;\n\
https.request(unrelated, () => {});\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S4830"), 2);
    }

    #[test]
    fn certificate_validation_behavior_is_preserved_alongside_hostname_checks() {
        let source = "const https = require('https');\nhttps.request({ rejectUnauthorized: false, checkServerIdentity: (_hostname, _certificate) => undefined }, () => {});\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S4830"), 1);
        assert_eq!(count_key(&js_keys(source), "javascript:S5527"), 1);
    }
}
