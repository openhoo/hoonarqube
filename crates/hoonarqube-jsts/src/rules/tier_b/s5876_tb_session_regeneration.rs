// Rule module s5876_tb_session_regeneration.
use crate::rules::batch5::collectors::{SecurityBindingResolver, SecurityFactory, SecurityModule};
use crate::rules::shared::argument_expression;
use crate::support::{
    IssueSink, RuleScope, expression_root_name, span_text_contains, unparenthesized,
};
use oxc_ast::ast::{CallExpression, Expression};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::walk_call_expression;
use oxc_semantic::Semantic;
use oxc_span::{GetSpan, Span};

/// `S5876`: login handlers that keep the pre-authentication session.
pub(crate) fn check_tb_session_regeneration(
    program: &oxc_ast::ast::Program<'_>,
    source: &str,
    semantic: Option<&Semantic<'_>>,
    sink: &mut IssueSink<'_>,
) {
    let mut collector = SessionRegenerationCollector {
        security_bindings: SecurityBindingResolver::new(program, semantic),
        ..Default::default()
    };
    collector.visit_program(program);
    for handler_span in collector.sites {
        let touches_session = span_text_contains(source, handler_span, "session");
        let regenerates = span_text_contains(source, handler_span, ".regenerate(");
        if (touches_session || collector.passport_login_spans.contains(&handler_span))
            && !regenerates
        {
            sink.emit_span(
                RuleScope::Both,
                "S5876",
                "Regenerate the session after login to prevent session fixation.",
                handler_span,
            );
        }
    }
}

#[derive(Default)]
pub(crate) struct SessionRegenerationCollector {
    pub(crate) sites: Vec<Span>,
    pub(crate) passport_login_spans: Vec<Span>,
    pub(crate) security_bindings: SecurityBindingResolver,
}

impl<'p> Visit<'p> for SessionRegenerationCollector {
    fn visit_call_expression(&mut self, call: &CallExpression<'p>) {
        let Expression::StaticMemberExpression(member) = &call.callee else {
            walk_call_expression(self, call);
            return;
        };
        let app_fallback = expression_root_name(&member.object) == Some("app")
            && self.security_bindings.symbol(&member.object).is_none();
        if member.property.name != "post"
            || ((!self.security_bindings.is_factory(
                &member.object,
                SecurityFactory::ExpressApp,
                call.span().start,
            ) && !self.security_bindings.is_factory(
                &member.object,
                SecurityFactory::ExpressRouter,
                call.span().start,
            )) && !app_fallback)
        {
            walk_call_expression(self, call);
            return;
        }
        if let Some(path) = call.arguments.first().and_then(argument_expression)
            && is_login_path(unparenthesized(path))
            && let Some(handler) = call.arguments.last().and_then(argument_expression)
        {
            let has_passport = call.arguments.iter().skip(1).any(|argument| {
                argument_expression(argument).is_some_and(|expression| {
                    if let Expression::CallExpression(auth) = unparenthesized(expression) {
                        self.security_bindings.is_module_member(
                            &auth.callee,
                            SecurityModule::Passport,
                            "authenticate",
                            auth.span().start,
                        )
                    } else {
                        false
                    }
                })
            });
            self.sites.push(handler.span());
            if has_passport {
                self.passport_login_spans.push(handler.span());
            }
        }
        walk_call_expression(self, call);
    }
}

fn is_login_path(expression: &Expression<'_>) -> bool {
    matches!(
        expression,
        Expression::StringLiteral(literal)
            if literal.value.as_str() == "/login"
                || literal.value.as_str() == "/signin"
                || literal.value.as_str() == "/sign-in"
    )
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn login_without_session_regeneration_flagged() {
        let flagged = js(
            "app.post('/login', (req, res) => {\n  req.session.user = req.body.user;\n  res.redirect('/');\n});\n",
        );
        assert_eq!(filtered(&flagged, "S5876").len(), 1);
        let regenerated = js(
            "app.post('/login', (req, res) => {\n  req.session.regenerate(() => {});\n  res.redirect('/');\n});\n",
        );
        assert_eq!(filtered(&regenerated, "S5876").len(), 0);
        let other_path = js("app.post('/profile', (req, res) => {\n  res.send('ok');\n});\n");
        assert_eq!(filtered(&other_path, "S5876").len(), 0);
    }
}
