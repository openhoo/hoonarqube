use crate::rules::batch5::collectors::{SecurityHotspotCollector, SecurityModule};
use crate::support::{RuleScope, unparenthesized};
use oxc_ast::ast::{CallExpression, StringLiteral};
use oxc_span::GetSpan;

impl SecurityHotspotCollector<'_, '_> {
    /// `S5332`: cleartext modules pulled in through the Node loader.
    pub(crate) fn check_cleartext_require(&mut self, call: &CallExpression<'_>) {
        let is_loader_call = matches!(
            unparenthesized(&call.callee),
            oxc_ast::ast::Expression::Identifier(identifier) if identifier.name == "require"
        );
        let is_http = is_loader_call
            && (self.security_bindings.is_call_module(
                call,
                SecurityModule::Http,
                call.span().start,
            ) || self.security_bindings.is_call_module(
                call,
                SecurityModule::Ws,
                call.span().start,
            ));
        if is_http {
            self.emit_cleartext(call.span());
        }
    }

    /// `S5332`: cleartext `http://` / `ws://` URLs, excluding localhost health
    /// endpoints that do not leave the local machine.
    pub(crate) fn check_cleartext_scheme(&mut self, literal: &StringLiteral<'_>) {
        let lowered = literal.value.to_ascii_lowercase();
        if (lowered.starts_with("http://") || lowered.starts_with("ws://"))
            && !is_localhost_url(&lowered)
        {
            self.emit_cleartext(literal.span());
        }
    }

    fn emit_cleartext(&mut self, span: oxc_span::Span) {
        self.sink.emit_span(
            RuleScope::Both,
            "S5332",
            "Use TLS-protected communication instead of this cleartext protocol.",
            span,
        );
    }
}

fn is_localhost_url(value: &str) -> bool {
    let Some(scheme_end) = value.find("://") else {
        return false;
    };
    let authority = &value[scheme_end + 3..];
    let authority_end = authority.find(['/', '?', '#']).unwrap_or(authority.len());
    let authority = &authority[..authority_end];
    if authority.is_empty() || authority.contains('@') {
        return false;
    }
    if let Some(end) = authority
        .strip_prefix('[')
        .and_then(|rest| rest.find(']').map(|i| i + 1))
    {
        let host = &authority[1..end - 1];
        let suffix = &authority[end..];
        return host == "::1"
            && (suffix.is_empty()
                || (suffix.starts_with(':')
                    && suffix[1..]
                        .chars()
                        .all(|character| character.is_ascii_digit())));
    }
    let (host, port) = authority
        .split_once(':')
        .map_or((authority, ""), |(host, port)| (host, port));
    (host == "localhost" || host == "127.0.0.1")
        && (port.is_empty() || port.chars().all(|character| character.is_ascii_digit()))
}
