use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::UNSAFE_REFERRER_POLICIES;
use crate::rules::batch5::collectors::first_string_argument;
use crate::rules::batch5::collectors::string_argument_at;
use crate::rules::batch5::collectors::string_property;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::rules::react_jsx::walker::duplicated_key_name;
use crate::rules::tier_c::walker::sink_callee_name;
use crate::support::RuleScope;
use crate::support::unparenthesized;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_ast::ast::ObjectProperty;
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S5122`: wildcard cross-origin policies in `cors` configurations.
    pub(crate) fn check_cors_wildcard(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) != Some("cors") {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(object) = unparenthesized(argument) else {
            return;
        };
        if string_property(object, "origin") == Some("*") {
            self.sink.emit_span(
                RuleScope::Both,
                "S5122",
                "Restrict cross-origin access to trusted origins instead of '*'.",
                call.span(),
            );
        }
    }

    /// `S2255`, `S5122`, `S5689`, `S5730`-`S5739`: security header values.
    pub(crate) fn check_header_call(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        let property: &str = &member.property.name;
        if property != "setHeader" && property != "append" {
            return;
        }
        let Some(header) = first_string_argument(call) else {
            return;
        };
        let Some(value) = string_argument_at(call, 1) else {
            return;
        };
        let lowered_value = value.to_ascii_lowercase();
        self.report_header_value(header, call, value, &lowered_value);
    }

    /// Reports the hotspot triggered by a security-header value, if any.
    fn report_header_value(
        &mut self,
        header: &str,
        call: &CallExpression<'_>,
        value: &str,
        lowered_value: &str,
    ) {
        match header.to_ascii_lowercase().as_str() {
            "set-cookie" => self.sink.emit_span(
                RuleScope::Both,
                "S2255",
                "Make sure this cookie is sent over HTTPS only.",
                call.span(),
            ),
            "access-control-allow-origin" if value == "*" => self.sink.emit_span(
                RuleScope::Both,
                "S5122",
                "Restrict cross-origin access to trusted origins instead of '*'.",
                call.span(),
            ),
            "x-powered-by" | "server" => self.sink.emit_span(
                RuleScope::Both,
                "S5689",
                "Do not disclose server technology in response headers.",
                call.span(),
            ),
            "content-security-policy" => {
                if !lowered_value.contains("upgrade-insecure-requests") {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S5730",
                        "Add 'upgrade-insecure-requests' to this Content Security Policy.",
                        call.span(),
                    );
                }
                if !lowered_value.contains("frame-ancestors") {
                    self.sink.emit_span(
                        RuleScope::Both,
                        "S5732",
                        "Protect against clickjacking with 'frame-ancestors'.",
                        call.span(),
                    );
                }
            }
            "referrer-policy" if UNSAFE_REFERRER_POLICIES.contains(&lowered_value) => {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S5736",
                    "Use a privacy-protecting 'Referrer-Policy' value.",
                    call.span(),
                );
            }
            "strict-transport-security" if lowered_value.contains("max-age=0") => {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S5739",
                    "Increase 'max-age' for Strict-Transport-Security.",
                    call.span(),
                );
            }
            "x-content-type-options" if lowered_value != "nosniff" => {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S5734",
                    "Serve 'nosniff' for X-Content-Type-Options.",
                    call.span(),
                );
            }
            "expect-ct" if lowered_value.contains("max-age=0") => {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S5742",
                    "Make sure this 'Expect-CT' policy still enforces Certificate Transparency.",
                    call.span(),
                );
            }
            "x-dns-prefetch-control" if lowered_value == "on" => {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S5743",
                    "Make sure browsers cannot perform DNS prefetching here.",
                    call.span(),
                );
            }
            _ => {}
        }
    }

    /// Table-driven option-object checks over every object literal.
    pub(crate) fn check_option_property(&mut self, property: &ObjectProperty<'_>) {
        let finding = match (duplicated_key_name(&property.key), &property.value) {
            (Some("rejectUnauthorized"), Expression::BooleanLiteral(literal)) if !literal.value => {
                Some(("S5527", "Do not disable TLS certificate verification."))
            }
            (Some("dotfiles"), Expression::StringLiteral(literal)) if literal.value == "allow" => {
                Some(("S5691", "Do not serve dotfiles to clients."))
            }
            (Some("autoescape"), Expression::BooleanLiteral(literal)) if !literal.value => Some((
                "S5247",
                "Enable automatic escaping in this template engine configuration.",
            )),
            (Some("frameguard"), Expression::BooleanLiteral(literal)) if !literal.value => Some((
                "S5732",
                "Protect against clickjacking with 'frame-ancestors'.",
            )),
            (Some("expectCt"), Expression::BooleanLiteral(literal)) if !literal.value => Some((
                "S5742",
                "Do not disable Certificate Transparency monitoring.",
            )),
            (Some("dnsPrefetch"), Expression::BooleanLiteral(literal)) if !literal.value => Some((
                "S5743",
                "Make sure browsers cannot perform DNS prefetching here.",
            )),
            (Some(key), Expression::StringLiteral(literal))
                if key.eq_ignore_ascii_case("x-dns-prefetch-control")
                    && literal.value.eq_ignore_ascii_case("on") =>
            {
                Some((
                    "S5743",
                    "Make sure browsers cannot perform DNS prefetching here.",
                ))
            }
            _ => None,
        };
        if let Some((rule, message)) = finding {
            self.sink
                .emit_span(RuleScope::Both, rule, message, property.key.span());
        }
    }
}
