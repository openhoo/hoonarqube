use crate::rules::batch5::collectors::{
    SecurityFactory, SecurityHotspotCollector, SecurityInstance, SecurityValue, boolean_property,
    object_property,
};
use crate::rules::shared::argument_expression;
use crate::support::RuleScope;
use crate::support::expression_root_name;
use crate::support::unparenthesized;
use oxc_ast::ast::{CallExpression, Expression, StaticMemberExpression};
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S2092` and `S3330`: secure cookie/session options.
    pub(crate) fn check_cookie_options(&mut self, call: &CallExpression<'_>) {
        let at = call.span().start;
        if self.check_cookie_session(call, at) {
            return;
        }
        if self.check_express_session(call, at) {
            return;
        }
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        if self.check_cookies_set(member, call, at) {
            return;
        }
        self.check_response_cookie(member, call);
    }

    fn check_cookie_session(&mut self, call: &CallExpression<'_>, at: u32) -> bool {
        if !self
            .security_bindings
            .is_call_factory(call, SecurityFactory::CookieSession, at)
        {
            return false;
        }
        if let Some(options) = call.arguments.first().and_then(argument_expression) {
            self.check_cookie_boolean(options, "secure", "S2092", call.span());
        }
        true
    }

    fn check_express_session(&mut self, call: &CallExpression<'_>, at: u32) -> bool {
        if !self.security_bindings.is_call_factory(
            call,
            SecurityFactory::ExpressSessionMiddleware,
            at,
        ) {
            return false;
        }
        if let Some(options) = call.arguments.first().and_then(argument_expression)
            && let Expression::ObjectExpression(options) = unparenthesized(options)
            && let Some(Expression::ObjectExpression(cookie)) = object_property(options, "cookie")
        {
            if boolean_property(cookie, "secure") != Some(true) {
                self.emit_cookie_issue("S2092", call.span());
            }
            if boolean_property(cookie, "httpOnly") != Some(true) {
                self.emit_cookie_issue("S3330", call.span());
            }
        }
        true
    }

    fn check_cookies_set(
        &mut self,
        member: &StaticMemberExpression<'_>,
        call: &CallExpression<'_>,
        at: u32,
    ) -> bool {
        if member.property.name != "set"
            || !self
                .security_bindings
                .is_instance(&member.object, SecurityInstance::Cookies, at)
        {
            return false;
        }
        if let Some(options) = call.arguments.get(2).and_then(argument_expression) {
            self.check_cookie_false(options, "secure", "S2092", at, call.span());
            self.check_cookie_false(options, "httpOnly", "S3330", at, call.span());
        }
        true
    }

    fn check_response_cookie(
        &mut self,
        member: &StaticMemberExpression<'_>,
        call: &CallExpression<'_>,
    ) {
        let rooted_at_response = matches!(
            expression_root_name(&member.object),
            Some("res" | "response")
        );
        if member.property.name != "cookie" || !rooted_at_response || call.arguments.len() < 3 {
            return;
        }
        let Some(options) = call.arguments.get(2).and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(object) = unparenthesized(options) else {
            return;
        };
        if boolean_property(object, "secure") != Some(true) {
            self.emit_cookie_issue("S2092", call.span());
        }
        if boolean_property(object, "httpOnly") != Some(true) {
            self.emit_cookie_issue("S3330", call.span());
        }
    }

    fn check_cookie_boolean(
        &mut self,
        options: &Expression<'_>,
        key: &str,
        rule: &str,
        span: oxc_span::Span,
    ) {
        let unsafe_value = match unparenthesized(options) {
            Expression::ObjectExpression(object) => boolean_property(object, key) != Some(true),
            _ => {
                self.security_bindings
                    .object_property(options, key, span.start)
                    != Some(SecurityValue::Boolean(true))
            }
        };
        if unsafe_value {
            self.emit_cookie_issue(rule, span);
        }
    }

    fn check_cookie_false(
        &mut self,
        options: &Expression<'_>,
        key: &str,
        rule: &str,
        at: u32,
        span: oxc_span::Span,
    ) {
        let value = match unparenthesized(options) {
            Expression::ObjectExpression(object) => {
                boolean_property(object, key).map(SecurityValue::Boolean)
            }
            _ => self.security_bindings.object_property(options, key, at),
        };
        if value == Some(SecurityValue::Boolean(false)) {
            self.emit_cookie_issue(rule, span);
        }
    }

    fn emit_cookie_issue(&mut self, rule: &str, span: oxc_span::Span) {
        let (message, rule) = match rule {
            "S2092" => ("Set the 'secure' cookie option to true.", "S2092"),
            _ => ("Set the 'httpOnly' cookie option to true.", "S3330"),
        };
        self.sink.emit_span(RuleScope::Both, rule, message, span);
    }
}
