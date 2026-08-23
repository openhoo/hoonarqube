// Residual rule machinery for 'batch5' (extracted from lib.rs).
use crate::JstsLanguage;
use crate::engine::scope_model::function_body_span;
use crate::engine::scope_model::function_parameters;
use crate::engine::scope_model::parameter_names;
use crate::rules::batch5::collectors::ANGULAR_BYPASS_METHODS;
use crate::rules::batch5::collectors::ARCHIVE_EXTRACT_APIS;
use crate::rules::batch5::collectors::CLEARTEXT_MODULES;
use crate::rules::batch5::collectors::CSP_FETCH_DIRECTIVES;
use crate::rules::batch5::collectors::ENCRYPT_API_NAMES;
use crate::rules::batch5::collectors::PATH_LOOKUP_APIS;
use crate::rules::batch5::collectors::RAW_SOCKET_MODULES;
use crate::rules::batch5::collectors::SENSITIVE_DATA_FRAGMENTS;
use crate::rules::batch5::collectors::SHELL_EXEC_NAMES;
use crate::rules::batch5::collectors::SecurityHotspotCollector;
use crate::rules::batch5::collectors::UNSAFE_REFERRER_POLICIES;
use crate::rules::batch5::collectors::WEAK_CIPHER_FAMILIES;
use crate::rules::batch5::collectors::WEAK_EC_CURVES;
use crate::rules::batch5::collectors::WEAK_HASH_ALGORITHMS;
use crate::rules::batch5::collectors::WEAK_HASH_FAMILY;
use crate::rules::batch5::collectors::WEAK_JWT_ALGORITHMS;
use crate::rules::batch5::collectors::WEAK_TLS_PROTOCOLS;
use crate::rules::batch5::collectors::boolean_property;
use crate::rules::batch5::collectors::first_string_argument;
use crate::rules::batch5::collectors::number_property;
use crate::rules::batch5::collectors::object_property;
use crate::rules::batch5::collectors::string_argument_at;
use crate::rules::batch5::collectors::string_property;
use crate::rules::batch5::s2187_test_framework_rules::TestFrameworkCollector;
use crate::rules::expression::collectors::CONSOLE_METHODS;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::rules::react_jsx::walker::duplicated_key_name;
use crate::rules::tier_c::walker::sink_callee_name;
use crate::support::{
    IssueSink, LineIndex, RuleScope, callee_name, constructor_name, expression_root_name,
    identifier_name, member_root_name, span_issue, span_text, span_text_contains,
    static_property_name, unparenthesized,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    AssignmentExpression, CallExpression, ExportDefaultDeclarationKind, Expression,
    ExpressionStatement, FunctionBody, ImportDeclaration, MemberExpression, NewExpression,
    ObjectProperty, ObjectPropertyKind, Statement, StringLiteral, TemplateLiteral, ThisExpression,
    VariableDeclarationKind,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::walk_catch_clause;
use oxc_ast_visit::walk::{
    walk_call_expression, walk_expression_statement, walk_function_body, walk_program,
    walk_this_expression,
};
use oxc_span::{GetSpan, Span};
use std::path::Path;

impl SecurityHotspotCollector<'_, '_> {
    /// `S2612` and `S4790`: weak algorithms in `createHash` calls.
    pub(crate) fn check_hash_sink(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) != Some("createHash") {
            return;
        }
        let Some(algorithm) = first_string_argument(call) else {
            return;
        };
        let lowered = algorithm.to_ascii_lowercase();
        if WEAK_HASH_ALGORITHMS.contains(&lowered.as_str()) {
            self.sink.emit_span(
                RuleScope::Both,
                "S2612",
                &format!("Make sure hashing with '{lowered}' is safe here."),
                call.span(),
            );
        }
        if WEAK_HASH_FAMILY.contains(&lowered.as_str()) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4790",
                &format!("Use a stronger hash algorithm than '{lowered}'."),
                call.span(),
            );
        }
    }

    /// `S4787`: encryption API usage worth reviewing.
    pub(crate) fn check_encrypt_api(&mut self, call: &CallExpression<'_>) {
        let Some(name) = sink_callee_name(&call.callee) else {
            return;
        };
        if ENCRYPT_API_NAMES.contains(&name) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4787",
                "Make sure using this encryption API is safe here.",
                call.span(),
            );
        }
    }

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

    /// `S5542`: ECB modes and CBC calls without an initialization vector.
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
        let missing_iv = lowered.contains("cbc")
            && call
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
        }
    }

    /// `S5547`: broken cipher families in `createCipheriv` calls.
    pub(crate) fn check_weak_cipher(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) != Some("createCipheriv") {
            return;
        }
        let Some(cipher) = first_string_argument(call) else {
            return;
        };
        let lowered = cipher.to_ascii_lowercase();
        let family = lowered.split('-').next().unwrap_or_default();
        if WEAK_CIPHER_FAMILIES.contains(&family) {
            self.sink.emit_span(
                RuleScope::Both,
                "S5547",
                &format!("Make sure encrypting with '{cipher}' is safe here."),
                call.span(),
            );
        }
    }

    /// `S4721` and `S4036`: shell-interpreter sinks and PATH lookups.
    pub(crate) fn check_shell_exec(&mut self, call: &CallExpression<'_>) {
        let Some(name) = sink_callee_name(&call.callee) else {
            return;
        };
        if SHELL_EXEC_NAMES.contains(&name) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4721",
                "Prefer 'spawn' over 'exec': 'exec' runs a shell interpreter.",
                call.span(),
            );
        }
        if PATH_LOOKUP_APIS.contains(&name)
            && let Some(executable) = first_string_argument(call)
            && !executable.contains('/')
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4036",
                "Specify the full path to this executable.",
                call.span(),
            );
        }
    }

    /// `S2245`: nondeterministic randomness worth reviewing.
    pub(crate) fn check_math_random(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        if member.property.name == "random" && expression_root_name(&member.object) == Some("Math")
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S2245",
                "Make sure using 'Math.random()' is safe here.",
                call.span(),
            );
        }
    }

    /// `S5659`: weak JWT signing or verification algorithms.
    pub(crate) fn check_jwt_algorithms(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        if !(member.property.name == "sign" || member.property.name == "verify")
            || expression_root_name(&member.object) != Some("jwt")
        {
            return;
        }
        let weak = call.arguments.iter().any(|argument| {
            let Some(expression) = argument_expression(argument) else {
                return false;
            };
            match unparenthesized(expression) {
                Expression::StringLiteral(literal) => {
                    WEAK_JWT_ALGORITHMS.contains(&literal.value.as_str())
                }
                Expression::ObjectExpression(object) => string_property(object, "algorithm")
                    .is_some_and(|algorithm| WEAK_JWT_ALGORITHMS.contains(&algorithm)),
                _ => false,
            }
        });
        if weak {
            self.sink.emit_span(
                RuleScope::Both,
                "S5659",
                "Sign and verify JWTs with strong algorithms only.",
                call.span(),
            );
        }
    }

    /// `S6268`: Angular sanitizer bypass methods.
    pub(crate) fn check_angular_bypass(&mut self, call: &CallExpression<'_>) {
        let Some(name) = sink_callee_name(&call.callee) else {
            return;
        };
        if ANGULAR_BYPASS_METHODS.contains(&name) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6268",
                "Make sure bypassing Angular's built-in sanitization is safe here.",
                call.span(),
            );
        }
    }

    /// `S2819`: message handlers that never consult `origin`.
    pub(crate) fn check_message_handler(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        if !(member.property.name == "on" || member.property.name == "addEventListener") {
            return;
        }
        let Some(channel) = first_string_argument(call) else {
            return;
        };
        if !matches!(channel, "message" | "onmessage") {
            return;
        }
        let Some(handler) = call.arguments.get(1).and_then(argument_expression) else {
            return;
        };
        let body_span = match unparenthesized(handler) {
            Expression::FunctionExpression(function) => {
                function.body.as_deref().map(oxc_span::GetSpan::span)
            }
            Expression::ArrowFunctionExpression(arrow) => Some(arrow.body.span()),
            _ => None,
        };
        let Some(body_span) = body_span else {
            return;
        };
        if span_text_contains(self.source, body_span, "origin") {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S2819",
            "Make sure this message handler verifies the sender origin.",
            call.span(),
        );
    }

    /// `S4423`: weak TLS protocol versions in string literals.
    pub(crate) fn check_tls_protocol_literal(&mut self, literal: &StringLiteral<'_>) {
        let lowered = literal.value.to_ascii_lowercase();
        if WEAK_TLS_PROTOCOLS.contains(&lowered.as_str()) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4423",
                "Make sure this weak TLS protocol version is safe here.",
                literal.span(),
            );
        }
    }
    /// `S5148`: `window.open` features strings lacking `noopener`.
    pub(crate) fn check_window_open(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) != Some("open") || call.arguments.len() < 3 {
            return;
        }
        let Some(features) = call.arguments.get(2).and_then(argument_expression) else {
            return;
        };
        let Expression::StringLiteral(literal) = unparenthesized(features) else {
            return;
        };
        let lowered = literal.value.to_ascii_lowercase();
        if !lowered.contains("noopener") && !lowered.contains("noreferrer") {
            self.sink.emit_span(
                RuleScope::Both,
                "S5148",
                "Add 'noopener' to this window.open features string.",
                call.span(),
            );
        }
    }

    /// `S5757`: console logging of sensitive-looking values.
    pub(crate) fn check_sensitive_log(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        let property: &str = &member.property.name;
        if expression_root_name(&member.object) != Some("console")
            || !CONSOLE_METHODS.contains(&property)
        {
            return;
        }
        let sensitive = call.arguments.iter().any(|argument| {
            let Some(expression) = argument_expression(argument) else {
                return false;
            };
            let text = span_text(self.source, expression.span()).to_ascii_lowercase();
            SENSITIVE_DATA_FRAGMENTS
                .iter()
                .any(|fragment| text.contains(fragment))
        });
        if sensitive {
            self.sink.emit_span(
                RuleScope::Both,
                "S5757",
                "Make sure this logged data is not sensitive.",
                call.span(),
            );
        }
    }

    /// `S4507`: error-handling middleware mounted outside debug guards.
    pub(crate) fn check_error_middleware(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        let property: &str = &member.property.name;
        if property != "use" || expression_root_name(&member.object) != Some("app") {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let flagged = match unparenthesized(argument) {
            Expression::Identifier(identifier) => identifier.name == "errorHandler",
            Expression::StringLiteral(literal) => literal.value.as_str() == "errorHandler",
            _ => false,
        };
        if flagged {
            self.sink.emit_span(
                RuleScope::Both,
                "S4507",
                "Only enable this error-handling middleware while debugging.",
                call.span(),
            );
        }
    }

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

    /// `S5332`: cleartext modules pulled in through `require`.
    pub(crate) fn check_cleartext_require(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) != Some("require") {
            return;
        }
        if let Some(module) = first_string_argument(call)
            && CLEARTEXT_MODULES.contains(&module)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S5332",
                "Use TLS-protected communication instead of this cleartext protocol.",
                call.span(),
            );
        }
    }

    /// `S5604`: sensitive permission surfaces worth reviewing.
    pub(crate) fn check_sensitive_permission(&mut self, member: &MemberExpression<'_>) {
        let Some(property) = static_property_name(member) else {
            return;
        };
        let flagged = (property == "geolocation" && member_root_name(member) == Some("navigator"))
            || (property == "requestPermission"
                && member_root_name(member) == Some("Notification"));
        if flagged {
            self.sink.emit_span(
                RuleScope::Both,
                "S5604",
                "Make sure requesting this sensitive permission is safe here.",
                member.span(),
            );
        }
    }

    /// `S5759`: trusting the `X-Forwarded-For` header.
    pub(crate) fn check_forwarded_header_trust(&mut self, member: &MemberExpression<'_>) {
        let MemberExpression::ComputedMemberExpression(computed) = member else {
            return;
        };
        let Expression::StringLiteral(literal) = &computed.expression else {
            return;
        };
        if literal.value.to_ascii_lowercase() == "x-forwarded-for" {
            self.sink.emit_span(
                RuleScope::Both,
                "S5759",
                "Make sure this forwarded header comes from a trusted source.",
                member.span(),
            );
        }
    }

    /// `S4830`: globally disabled TLS certificate validation.
    pub(crate) fn check_tls_validation_disabled(&mut self, assignment: &AssignmentExpression<'_>) {
        let Some(oxc_ast::ast::SimpleAssignmentTarget::StaticMemberExpression(member)) =
            assignment.left.as_simple_assignment_target()
        else {
            return;
        };
        if member.property.name == "NODE_TLS_REJECT_UNAUTHORIZED"
            && expression_root_name(&member.object) == Some("process")
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4830",
                "Do not disable TLS certificate validation globally.",
                assignment.span(),
            );
        }
    }

    /// `S5332`: cleartext `http://` / `ws://` URLs in string literals.
    pub(crate) fn check_cleartext_scheme(&mut self, literal: &StringLiteral<'_>) {
        let lowered = literal.value.to_ascii_lowercase();
        if lowered.starts_with("http://") || lowered.starts_with("ws://") {
            self.sink.emit_span(
                RuleScope::Both,
                "S5332",
                "Use TLS-protected communication instead of this cleartext protocol.",
                literal.span(),
            );
        }
    }

    /// `S2092` and `S3330`: cookie options missing `secure` / `httpOnly`.
    pub(crate) fn check_cookie_options(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        let property: &str = &member.property.name;
        let rooted_at_response = matches!(
            expression_root_name(&member.object),
            Some("res" | "response")
        );
        if property != "cookie" || !rooted_at_response || call.arguments.len() < 3 {
            return;
        }
        let Some(options) = call.arguments.get(2).and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(object) = unparenthesized(options) else {
            return;
        };
        if boolean_property(object, "secure") != Some(true) {
            self.sink.emit_span(
                RuleScope::Both,
                "S2092",
                "Set the 'secure' cookie option to true.",
                call.span(),
            );
        }
        if boolean_property(object, "httpOnly") != Some(true) {
            self.sink.emit_span(
                RuleScope::Both,
                "S3330",
                "Set the 'httpOnly' cookie option to true.",
                call.span(),
            );
        }
    }

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
            self.sink.emit_span(
                RuleScope::Both,
                "S2755",
                "Make sure entity substitution is disabled for this XML parser.",
                call.span(),
            );
        }
    }

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

    /// `S5693`: body parsers configured without a size limit.
    pub(crate) fn check_body_parser_limit(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        let property: &str = &member.property.name;
        if property != "json" && property != "urlencoded" && property != "text" {
            return;
        }
        let root = expression_root_name(&member.object);
        if !matches!(root, Some("express" | "bodyParser")) {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(object) = unparenthesized(argument) else {
            return;
        };
        if object_property(object, "limit").is_none() {
            self.sink.emit_span(
                RuleScope::Both,
                "S5693",
                "Configure a request-body size limit ('limit').",
                call.span(),
            );
        }
    }

    /// `S4502`: CSRF protection switched off for explicit route lists.
    pub(crate) fn check_csrf_disabled(&mut self, call: &CallExpression<'_>) {
        if !matches!(sink_callee_name(&call.callee), Some("csrf" | "csurf")) {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(object) = unparenthesized(argument) else {
            return;
        };
        let Some(Expression::ArrayExpression(routes)) = object_property(object, "ignoreRoutes")
        else {
            return;
        };
        if !routes.elements.is_empty() {
            self.sink.emit_span(
                RuleScope::Both,
                "S4502",
                "Make sure disabling CSRF protection for these routes is safe.",
                call.span(),
            );
        }
    }

    /// `S5042`: archive extraction without extraction limits.
    pub(crate) fn check_archive_extraction(&mut self, call: &CallExpression<'_>) {
        let Some(name) = sink_callee_name(&call.callee) else {
            return;
        };
        if ARCHIVE_EXTRACT_APIS.contains(&name) {
            self.sink.emit_span(
                RuleScope::Both,
                "S5042",
                "Make sure extracting this archive safely limits file count and size.",
                call.span(),
            );
        }
    }

    /// `S5728`: helmet configurations disabling the CSP or its directives.
    pub(crate) fn check_helmet_config(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) != Some("helmet") {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(options) = unparenthesized(argument) else {
            return;
        };
        if boolean_property(options, "contentSecurityPolicy") == Some(false) {
            self.sink.emit_span(
                RuleScope::Both,
                "S5728",
                "Do not disable the Content Security Policy entirely.",
                call.span(),
            );
            return;
        }
        let Some(Expression::ObjectExpression(csp)) =
            object_property(options, "contentSecurityPolicy")
        else {
            return;
        };
        let Some(Expression::ObjectExpression(directives)) = object_property(csp, "directives")
        else {
            return;
        };
        for directive in &directives.properties {
            let ObjectPropertyKind::ObjectProperty(inner) = directive else {
                continue;
            };
            let disabled = duplicated_key_name(&inner.key)
                .is_some_and(|key| CSP_FETCH_DIRECTIVES.contains(&key))
                && match &inner.value {
                    Expression::BooleanLiteral(literal) => !literal.value,
                    Expression::ArrayExpression(items) => items.elements.is_empty(),
                    _ => false,
                };
            if disabled {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S5728",
                    "Do not disable this Content Security Policy directive.",
                    inner.key.span(),
                );
            }
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
            "referrer-policy" if UNSAFE_REFERRER_POLICIES.contains(&lowered_value.as_str()) => {
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

    /// `S4829`: standard-input reads worth reviewing.
    pub(crate) fn check_standard_input_reads(&mut self, it: &MemberExpression<'_>) {
        if member_root_name(it) == Some("process") && static_property_name(it) == Some("stdin") {
            self.sink.emit_span(
                RuleScope::Both,
                "S4829",
                "Make sure reading from the standard input is safe here.",
                it.span(),
            );
        }
    }

    /// `S4817`: `XPath` evaluation entry points worth reviewing.
    pub(crate) fn check_xpath_usage(&mut self, call: &CallExpression<'_>) {
        let mut flagged = false;
        if let Expression::StaticMemberExpression(member) = &call.callee
            && member.property.name == "evaluate"
            && expression_root_name(&member.object) == Some("document")
        {
            flagged = true;
        }
        if !flagged
            && sink_callee_name(&call.callee) == Some("require")
            && first_string_argument(call) == Some("xpath")
        {
            flagged = true;
        }
        if flagged {
            self.sink.emit_span(
                RuleScope::Both,
                "S4817",
                "Make sure evaluating this XPath expression is safe here.",
                call.span(),
            );
        }
    }

    /// `S4817`: `xpath` module imports.
    pub(crate) fn check_xpath_module_import(&mut self, declaration: &ImportDeclaration<'_>) {
        if declaration.source.value == "xpath" {
            self.sink.emit_span(
                RuleScope::Both,
                "S4817",
                "Make sure evaluating these XPath expressions is safe here.",
                declaration.span(),
            );
        }
    }

    /// `S4817`: dedicated `XPathEvaluator` constructions.
    pub(crate) fn check_new_xpath_evaluator(&mut self, constructor: &NewExpression<'_>) {
        if identifier_name(&constructor.callee) == Some("XPathEvaluator") {
            self.sink.emit_span(
                RuleScope::Both,
                "S4817",
                "Make sure evaluating XPath expressions with this evaluator is safe here.",
                constructor.span(),
            );
        }
    }

    /// `S4818`: raw-socket module requires.
    pub(crate) fn check_socket_require(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) == Some("require")
            && first_string_argument(call)
                .is_some_and(|module| RAW_SOCKET_MODULES.contains(&module))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4818",
                "Make sure using this raw socket is safe here.",
                call.span(),
            );
        }
    }

    /// `S4818`: raw-socket module imports.
    pub(crate) fn check_socket_module_import(&mut self, declaration: &ImportDeclaration<'_>) {
        if RAW_SOCKET_MODULES.contains(&declaration.source.value.as_str()) {
            self.sink.emit_span(
                RuleScope::Both,
                "S4818",
                "Make sure using these raw sockets is safe here.",
                declaration.span(),
            );
        }
    }

    /// `S4818`: direct socket constructions over `net`/`dgram`.
    pub(crate) fn check_new_raw_socket(&mut self, constructor: &NewExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &constructor.callee else {
            return;
        };
        if matches!(expression_root_name(&member.object), Some("net" | "dgram"))
            && matches!(member.property.name.as_str(), "Socket" | "Server")
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4818",
                "Make sure opening this raw socket is safe here.",
                constructor.span(),
            );
        }
    }

    /// `S4823`: command-line argument accesses worth reviewing.
    pub(crate) fn check_command_line_arguments(&mut self, it: &MemberExpression<'_>) {
        if member_root_name(it) == Some("process")
            && matches!(static_property_name(it), Some("argv" | "execArgv"))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S4823",
                "Make sure using command line arguments is safe here.",
                it.span(),
            );
        }
    }

    /// `S6299`: `v-html` usages inside template strings worth reviewing.
    pub(crate) fn check_vue_v_html_string(&mut self, value: &str, span: Span) {
        if value.contains("v-html") {
            self.sink.emit_span(
                RuleScope::Both,
                "S6299",
                "Make sure disabling Vue.js built-in escaping with 'v-html' is safe here.",
                span,
            );
        }
    }

    /// `S6299`: `v-html` usages inside template literals.
    pub(crate) fn check_vue_v_html_template(&mut self, literal: &TemplateLiteral<'_>) {
        if literal
            .quasis
            .iter()
            .any(|element| element.value.raw.contains("v-html"))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6299",
                "Make sure disabling Vue.js built-in escaping with 'v-html' is safe here.",
                literal.span,
            );
        }
    }

    /// `S6245`: S3 bucket creations without a server-side-encryption option.
    pub(crate) fn check_s3_create_bucket(&mut self, call: &CallExpression<'_>) {
        if sink_callee_name(&call.callee) != Some("createBucket") {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(options) = unparenthesized(argument) else {
            return;
        };
        if object_property(options, "ServerSideEncryptionConfiguration").is_none() {
            self.sink.emit_span(
                RuleScope::Both,
                "S6245",
                "Enable server-side encryption for this S3 bucket.",
                call.span(),
            );
        }
    }

    /// `S6245`: `CreateBucketCommand` inputs without server-side encryption.
    pub(crate) fn check_new_s3_bucket_command(&mut self, constructor: &NewExpression<'_>) {
        if identifier_name(&constructor.callee) != Some("CreateBucketCommand") {
            return;
        }
        let Some(argument) = constructor.arguments.first().and_then(argument_expression) else {
            return;
        };
        let Expression::ObjectExpression(options) = unparenthesized(argument) else {
            return;
        };
        if object_property(options, "ServerSideEncryptionConfiguration").is_none() {
            self.sink.emit_span(
                RuleScope::Both,
                "S6245",
                "Enable server-side encryption for this S3 bucket.",
                constructor.span(),
            );
        }
    }
}

/// Test-runner globals whose calls mark a file as containing tests.
pub(crate) const TEST_FRAMEWORK_GLOBALS: [&str; 5] =
    ["describe", "it", "test", "context", "specify"];

/// Skipped-test spellings `S1607` flags.
pub(crate) const SKIPPED_TEST_NAMES: [&str; 3] = ["xit", "xdescribe", "xcontext"];

/// Focused-test spellings `S6426` flags.
pub(crate) const FOCUSED_TEST_NAMES: [&str; 2] = ["fit", "fdescribe"];

/// Fragments whose absence in a callback body means `S2699` flags it.
pub(crate) const ASSERTION_MARKERS: [&str; 4] = ["expect(", "assert.", "assert(", "should"];

/// Chai language chains (properties that assert nothing by themselves).
pub(crate) const CHAI_LANGUAGE_PROPS: [&str; 14] = [
    "to", "be", "been", "is", "that", "which", "and", "has", "have", "with", "at", "of", "same",
    "not",
];

/// Chai matcher methods counted by the `S6092` chain check.
pub(crate) const CHAI_MATCHER_METHODS: [&str; 10] = [
    "equal", "eql", "match", "include", "contain", "keys", "property", "lengthOf", "above", "below",
];

/// Walks `expect(x).to.equal(y)`-style callees down to their `expect` root,
/// collecting member links outermost-first across chained matcher calls.
pub(crate) fn deconstruct_expect_chain<'a>(
    expression: &'a Expression<'a>,
    links: &mut Vec<&'a str>,
) -> Option<&'a Expression<'a>> {
    match unparenthesized(expression) {
        Expression::StaticMemberExpression(member) => {
            let name: &str = &member.property.name;
            links.push(name);
            deconstruct_expect_chain(&member.object, links)
        }
        Expression::CallExpression(call) if callee_name(call) != Some("expect") => {
            deconstruct_expect_chain(&call.callee, links)
        }
        Expression::CallExpression(call)
            if callee_name(call) == Some("expect") && call.arguments.len() == 1 =>
        {
            call.arguments.first().and_then(argument_expression)
        }
        _ => None,
    }
}

/// Whether trimmed text still holds statements after the last `done()` call.
pub(crate) fn statements_follow_done(text: &str) -> bool {
    let Some(position) = text.rfind("done()") else {
        return false;
    };
    let remainder = text[position + "done()".len()..].trim_matches(|character: char| {
        character.is_whitespace() || character == '}' || character == ';'
    });
    !remainder.is_empty()
}

/// Collector for the remaining single-file Tier-A checks.
pub(crate) struct MiscCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
    /// Number of enclosing function boundaries (`S2990`).
    pub(crate) function_depth: u32,
}

impl<'a> Visit<'a> for MiscCollector<'_> {
    fn visit_program(&mut self, it: &oxc_ast::ast::Program<'a>) {
        // `S3798` (JavaScript-only): global `var` / function declarations.
        for statement in &it.body {
            match statement {
                Statement::VariableDeclaration(declaration)
                    if declaration.kind == VariableDeclarationKind::Var =>
                {
                    for declarator in &declaration.declarations {
                        self.sink.emit_span(
                            RuleScope::JsOnly,
                            "S3798",
                            "Declare this symbol in a narrower scope instead of globally.",
                            declarator.span(),
                        );
                    }
                }
                Statement::FunctionDeclaration(function) => {
                    self.sink.emit_span(
                        RuleScope::JsOnly,
                        "S3798",
                        "Declare this function in a narrower scope instead of globally.",
                        function.span(),
                    );
                }
                _ => {}
            }
        }
        walk_program(self, it);
    }

    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        // `S1539`: a surviving string-literal `"use strict"` statement is by
        // definition outside a directive prologue (valid ones become
        // directive nodes during parsing).
        if let Expression::StringLiteral(literal) = unparenthesized(&it.expression)
            && literal.value == "use strict"
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S1539",
                "Move this 'use strict' directive to the top of its enclosing scope.",
                it.span(),
            );
        }
        walk_expression_statement(self, it);
    }

    fn visit_this_expression(&mut self, it: &ThisExpression) {
        // `S2990`: `this` outside any function refers to the global object.
        if self.function_depth == 0 {
            self.sink.emit_span(
                RuleScope::Both,
                "S2990",
                "Remove this 'this'; it refers to the global object at module level.",
                it.span(),
            );
        }
        walk_this_expression(self, it);
    }

    fn visit_function_body(&mut self, it: &FunctionBody<'a>) {
        // Regular functions create a new `this` binding; arrows do not.
        self.function_depth += 1;
        walk_function_body(self, it);
        self.function_depth -= 1;
    }
}

/// Case- and separator-insensitive form used to compare declared names with
/// file names.
pub(crate) fn normalized_name(name: &str) -> String {
    name.chars()
        .filter(|character| character.is_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase()
}

/// Declared name of a default export, if it is statically knowable.
pub(crate) fn default_export_name<'a>(
    program: &'a oxc_ast::ast::Program<'a>,
) -> Option<(&'a str, Span)> {
    for statement in &program.body {
        let Statement::ExportDefaultDeclaration(export) = statement else {
            continue;
        };
        return match &export.declaration {
            ExportDefaultDeclarationKind::FunctionDeclaration(function) => {
                let id = function.id.as_ref()?;
                Some((&id.name, export.span()))
            }
            ExportDefaultDeclarationKind::ClassDeclaration(class) => {
                let id = class.id.as_ref()?;
                Some((&id.name, export.span()))
            }
            _ => {
                if let Some(expression) = export.declaration.as_expression() {
                    match unparenthesized(expression) {
                        Expression::Identifier(identifier) => {
                            Some((&identifier.name, export.span()))
                        }
                        _ => None,
                    }
                } else {
                    None
                }
            }
        };
    }
    None
}

/// `S3317`: the default-exported name should echo the file stem.
pub(crate) fn check_default_export_name(
    program: &oxc_ast::ast::Program<'_>,
    path: &Path,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let Some(stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return issues;
    };
    if let Some((name, span)) = default_export_name(program)
        && normalized_name(name) != normalized_name(stem)
    {
        issues.push(span_issue(
            index,
            format!("{}:S3317", language.prefix()),
            format!("Rename this default export; '{name}' does not match the file name '{stem}'."),
            span,
        ));
    }
    issues
}

/// Module specifier of an import, stripped of its relative marker.
pub(crate) fn relative_module_stem(specifier: &str) -> Option<String> {
    let stripped = specifier.strip_prefix("./").unwrap_or(specifier);
    if stripped.starts_with('.') || specifier.starts_with('/') {
        return None;
    }
    Path::new(stripped)
        .file_stem()
        .and_then(|stem| stem.to_str())
        .map(ToOwned::to_owned)
}

/// `S7060`: imports whose specifier resolves to the importing file itself.
pub(crate) fn check_self_imports(
    program: &oxc_ast::ast::Program<'_>,
    path: &Path,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut issues = Vec::new();
    let Some(self_stem) = path.file_stem().and_then(|stem| stem.to_str()) else {
        return issues;
    };
    for statement in &program.body {
        if let Statement::ImportDeclaration(import) = statement
            && relative_module_stem(&import.source.value)
                .is_some_and(|stem| normalized_name(&stem) == normalized_name(self_stem))
        {
            issues.push(span_issue(
                index,
                format!("{}:S7060", language.prefix()),
                "Remove this import: the module resolves to the importing file itself.",
                import.span(),
            ));
        }
    }
    issues
}

pub(crate) const SHELL_EXEC_FUNCTIONS: [&str; 5] =
    ["exec", "execSync", "spawn", "spawnSync", "execFile"];

pub(crate) fn static_command_text(expression: &Expression<'_>) -> Option<String> {
    match expression {
        Expression::StringLiteral(literal) => Some(literal.value.to_string()),
        Expression::TemplateLiteral(template) if template.expressions.is_empty() => Some(
            template
                .quasis
                .iter()
                .map(|quasi| quasi.value.raw.to_string())
                .collect(),
        ),
        _ => None,
    }
}

pub(crate) fn is_unpinned_npm_install(command: &str) -> bool {
    let tokens: Vec<&str> = command.split_whitespace().collect();
    if tokens.first() != Some(&"npm") || !matches!(tokens.get(1), Some(&"install" | &"i" | &"add"))
    {
        return false;
    }
    tokens[2..]
        .iter()
        .filter(|token| !token.starts_with('-'))
        .any(|token| !token.contains('@') && !token.contains('#') && !token.contains("://"))
}

impl<'a> Visit<'a> for TestFrameworkCollector<'_, '_> {
    fn visit_call_expression(&mut self, it: &CallExpression<'a>) {
        self.check_skipped_or_focused(it);
        self.check_this_timeout_zero(it);
        self.check_test_callback(it);
        self.check_expect_call(it);
        if let Some(name) = callee_name(it)
            && TEST_FRAMEWORK_GLOBALS.contains(&name)
        {
            self.test_calls_found = true;
        }
        walk_call_expression(self, it);
    }

    fn visit_expression_statement(&mut self, it: &ExpressionStatement<'a>) {
        self.check_incomplete_chai_chain(&it.expression);
        walk_expression_statement(self, it);
    }

    fn visit_catch_clause(&mut self, it: &oxc_ast::ast::CatchClause<'a>) {
        self.check_catch_without_assertion(it);
        walk_catch_clause(self, it);
    }
}

impl TestFrameworkCollector<'_, '_> {
    pub(crate) fn body_text(&self, span: Span) -> String {
        span_text(self.source, span).to_ascii_lowercase()
    }

    /// `S1607` and `S6426`: skipped and focused test spellings.
    pub(crate) fn check_skipped_or_focused(&mut self, call: &CallExpression<'_>) {
        if let Some(name) = callee_name(call) {
            if SKIPPED_TEST_NAMES.contains(&name) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S1607",
                    "Do not skip this test; remove it or fix it.",
                    call.span(),
                );
                return;
            }
            if FOCUSED_TEST_NAMES.contains(&name) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6426",
                    "Remove this exclusive test focus ('only').",
                    call.span(),
                );
                return;
            }
        }
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        let property: &str = &member.property.name;
        let root_is_test_global = expression_root_name(&member.object)
            .is_some_and(|root| TEST_FRAMEWORK_GLOBALS.contains(&root));
        if !root_is_test_global {
            return;
        }
        if property == "skip" {
            self.sink.emit_span(
                RuleScope::Both,
                "S1607",
                "Do not skip this test; remove it or fix it.",
                call.span(),
            );
        } else if property == "only" {
            self.sink.emit_span(
                RuleScope::Both,
                "S6426",
                "Remove this exclusive test focus ('only').",
                call.span(),
            );
        }
    }

    /// `S6080`: disabled timeouts via `this.timeout(0)`.
    pub(crate) fn check_this_timeout_zero(&mut self, call: &CallExpression<'_>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            return;
        };
        if member.property.name != "timeout"
            || !matches!(&member.object, Expression::ThisExpression(_))
        {
            return;
        }
        let zero = call
            .arguments
            .first()
            .and_then(argument_expression)
            .is_some_and(|argument| {
                matches!(
                    unparenthesized(argument),
                    Expression::NumericLiteral(literal) if literal.value == 0.0
                )
            });
        if zero {
            self.sink.emit_span(
                RuleScope::Both,
                "S6080",
                "Avoid disabling test timeouts with 'this.timeout(0)'.",
                call.span(),
            );
        }
    }

    /// `S2699`, `S5973`, and `S6079`: bodies of `it` / `test` callbacks.
    pub(crate) fn check_test_callback(&mut self, call: &CallExpression<'_>) {
        let Some(name) = callee_name(call) else {
            return;
        };
        if !matches!(name, "it" | "test" | "specify") {
            return;
        }
        let Some(callback) = call.arguments.last().and_then(argument_expression) else {
            return;
        };
        let Some(body_span) = function_body_span(callback) else {
            return;
        };
        let text = self.body_text(body_span);
        if !ASSERTION_MARKERS.iter().any(|marker| text.contains(marker)) {
            self.sink.emit_span(
                RuleScope::Both,
                "S2699",
                "Add an assertion to this test.",
                body_span,
            );
        }
        if text.contains("math.random()")
            || text.contains("date.now()")
            || text.contains("new date()")
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S5973",
                "Do not rely on nondeterministic values in this test.",
                body_span,
            );
        }
        let uses_done = function_parameters(callback)
            .is_some_and(|params| parameter_names(params).contains(&"done"));
        if uses_done && statements_follow_done(&text) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6079",
                "Move these statements before the 'done()' invocation.",
                body_span,
            );
        }
    }

    /// `S6092`, `S3415`, and `S5863`: chai assertions rooted at `expect`.
    pub(crate) fn check_expect_call(&mut self, call: &CallExpression<'_>) {
        let mut links: Vec<&str> = Vec::new();
        let Some(expect_argument) = deconstruct_expect_chain(&call.callee, &mut links) else {
            return;
        };
        let matcher_count = links
            .iter()
            .filter(|link| CHAI_MATCHER_METHODS.contains(link))
            .count();
        if matcher_count >= 2 {
            self.sink.emit_span(
                RuleScope::Both,
                "S6092",
                "Split this assertion chain into separate assertions.",
                call.span(),
            );
            return;
        }
        let Some(matcher) = links.first() else {
            return;
        };
        if !CHAI_MATCHER_METHODS.contains(matcher) {
            return;
        }
        let Some(argument) = call.arguments.first().and_then(argument_expression) else {
            return;
        };
        let expect_argument_is_literal = matches!(
            unparenthesized(expect_argument),
            Expression::StringLiteral(_)
                | Expression::NumericLiteral(_)
                | Expression::BooleanLiteral(_),
        );
        let argument_is_value = matches!(
            unparenthesized(argument),
            Expression::Identifier(_) | Expression::StaticMemberExpression(_),
        );
        let expect_text = span_text(self.source, expect_argument.span());
        let argument_text = span_text(self.source, argument.span());
        if expect_text.trim() == argument_text.trim() {
            self.sink.emit_span(
                RuleScope::Both,
                "S5863",
                "This assertion compares the value with itself.",
                call.span(),
            );
        } else if expect_argument_is_literal && argument_is_value {
            self.sink.emit_span(
                RuleScope::Both,
                "S3415",
                "The expected value appears to be the subject of this assertion; swap the arguments.",
                call.span(),
            );
        }
    }

    /// `S2970`: chai language chains that assert nothing.
    pub(crate) fn check_incomplete_chai_chain(&mut self, expression: &Expression<'_>) {
        let mut current = expression;
        let mut links: Vec<&str> = Vec::new();
        while let Expression::StaticMemberExpression(member) = current {
            let name: &str = &member.property.name;
            links.push(name);
            current = &member.object;
        }
        let rooted_at_expect = matches!(current, Expression::CallExpression(call) if callee_name(call) == Some("expect"));
        if rooted_at_expect
            && links.len() >= 2
            && links.iter().all(|link| CHAI_LANGUAGE_PROPS.contains(link))
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S2970",
                "Complete this assertion; these chai properties assert nothing.",
                expression.span(),
            );
        }
    }

    /// `S5958`: catch blocks without any assertion.
    pub(crate) fn check_catch_without_assertion(&mut self, clause: &oxc_ast::ast::CatchClause<'_>) {
        let text = self.body_text(clause.body.span());
        if !ASSERTION_MARKERS.iter().any(|marker| text.contains(marker)) {
            self.sink.emit_span(
                RuleScope::Both,
                "S5958",
                "Assert inside this catch block or use '.throw'/'rejects' matchers.",
                clause.body.span(),
            );
        }
    }
}
