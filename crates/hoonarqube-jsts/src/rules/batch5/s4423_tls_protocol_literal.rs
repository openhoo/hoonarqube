use crate::rules::batch5::collectors::{SecurityHotspotCollector, SecurityModule, SecurityValue};
use crate::rules::shared::argument_expression;
use crate::support::RuleScope;
use oxc_ast::ast::{CallExpression, Expression};
use oxc_span::GetSpan;

const WEAK_TLS_MINIMUMS: [&str; 2] = ["TLSv1", "TLSv1.1"];
const SECURE_PROTOCOL_ALLOWED_VALUES: [&str; 6] = [
    "TLSv1_2_method",
    "TLSv1_2_client_method",
    "TLSv1_2_server_method",
    "TLS_method",
    "TLS_client_method",
    "TLS_server_method",
];

impl SecurityHotspotCollector<'_, '_> {
    /// `S4423`: weak TLS protocol options on Node HTTPS/TLS entry points.
    ///
    /// The argument positions intentionally mirror the pinned owner:
    /// `https.request(options, callback)`, `tls.connect(...)`, and
    /// `tls.createSecureContext(options)`. The resolver supplies module and
    /// binding identity, so unrelated strings and shadowed native names are
    /// not treated as TLS configuration.
    pub(crate) fn check_tls_protocol_call(&mut self, call: &CallExpression<'_>) {
        let at = call.span().start;
        if self.security_bindings.is_module_member(
            &call.callee,
            SecurityModule::Https,
            "request",
            at,
        ) {
            self.check_tls_protocol_arguments(call, &[0, 1], at);
        } else if self.security_bindings.is_module_member(
            &call.callee,
            SecurityModule::Tls,
            "connect",
            at,
        ) {
            self.check_tls_protocol_arguments(call, &[0, 1, 2], at);
        } else if self.security_bindings.is_module_member(
            &call.callee,
            SecurityModule::Tls,
            "createSecureContext",
            at,
        ) {
            self.check_tls_protocol_arguments(call, &[0], at);
        }
    }

    fn check_tls_protocol_arguments(
        &mut self,
        call: &CallExpression<'_>,
        positions: &[usize],
        at: u32,
    ) {
        for &position in positions {
            let Some(options) = call.arguments.get(position).and_then(argument_expression) else {
                continue;
            };
            self.check_tls_protocol_options(options, at);
        }
    }

    fn check_tls_protocol_options(&mut self, options: &Expression<'_>, at: u32) {
        self.check_tls_protocol_option(options, "minVersion", at);
        self.check_tls_protocol_option(options, "maxVersion", at);
        self.check_tls_protocol_option(options, "secureProtocol", at);
    }

    fn check_tls_protocol_option(&mut self, options: &Expression<'_>, option_name: &str, at: u32) {
        let Some(value) = self
            .security_bindings
            .object_property(options, option_name, at)
        else {
            return;
        };
        let should_report = match option_name {
            "minVersion" | "maxVersion" => matches!(
                &value,
                SecurityValue::String(value)
                    if WEAK_TLS_MINIMUMS.contains(&value.as_str())
            ),
            "secureProtocol" => match &value {
                SecurityValue::String(value) => {
                    !SECURE_PROTOCOL_ALLOWED_VALUES.contains(&value.as_str())
                }
                SecurityValue::Boolean(_) | SecurityValue::Number(_) => true,
                _ => false,
            },
            _ => false,
        };
        if !should_report {
            return;
        }
        let Some(span) =
            self.security_bindings
                .object_property_source_span(options, option_name, at)
        else {
            return;
        };
        let message = match option_name {
            "secureProtocol" => "Change 'secureProtocol' to use at least TLS v1.2.",
            "minVersion" | "maxVersion" => {
                if option_name == "minVersion" {
                    "Change 'minVersion' to use at least TLS v1.2."
                } else {
                    "Change 'maxVersion' to use at least TLS v1.2."
                }
            }
            _ => return,
        };
        self.sink.emit_span(RuleScope::Both, "S4423", message, span);
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::{count_key, js, js_keys, ts_keys};

    #[test]
    fn shared_options_report_once_for_each_matching_call() {
        let source = "\
const https = require('node:https');\n\
const tls = require('node:tls');\n\
const options = { secureProtocol: 'TLSv1_method' };\n\
const request = https.request(options, res => res.resume());\n\
const socket = tls.connect(443, 'www.example.com', options, () => {});\n\
module.exports = { request, socket };\n";
        let report = js(source);
        let findings: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S4423")
            .collect();
        assert_eq!(findings.len(), 2);
        assert!(findings.iter().all(|issue| {
            issue.message == "Change 'secureProtocol' to use at least TLS v1.2."
                && issue.range.start.line == 3
                && issue.range.start.column == 34
                && issue.range.end.line == 3
                && issue.range.end.column == 48
        }));
    }

    #[test]
    fn min_and_max_version_are_checked_at_the_supported_argument_positions() {
        let source = "\
const tls = require('tls');\n\
tls.createSecureContext({ minVersion: 'TLSv1' });\n\
tls.connect(443, 'example.test', { maxVersion: 'TLSv1.1' }, () => {});\n";
        let findings = js_keys(source);
        assert_eq!(count_key(&findings, "javascript:S4423"), 2);

        let typescript = "\
import * as https from 'node:https';\n\
https.request({ minVersion: 'TLSv1' }, () => {});\n";
        assert_eq!(count_key(&ts_keys(typescript), "typescript:S4423"), 1);
    }

    #[test]
    fn unrelated_strings_safe_values_shadowed_modules_and_mutated_options_are_clean() {
        let source = "\
const prose = 'TLSv1';\n\
const https = require('node:https');\n\
const safe = { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.3', secureProtocol: 'TLS_method' };\n\
https.request(safe, () => {});\n\
const arbitrary = { minVersion: 'TLSv2' };\n\
https.request(arbitrary, () => {});\n\
function shadowed(https) {\n\
  https.request({ minVersion: 'TLSv1' }, () => {});\n\
}\n\
const changed = { minVersion: 'TLSv1' };\n\
changed.minVersion = 'TLSv1.2';\n\
https.request(changed, () => {});\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S4423"), 0);
    }

    #[test]
    fn destructured_native_aliases_keep_module_identity() {
        let source = "\
const { request } = require('node:https');\n\
request({ maxVersion: 'TLSv1.1' }, () => {});\n";
        assert_eq!(count_key(&js_keys(source), "javascript:S4423"), 1);
    }
}
