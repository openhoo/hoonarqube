use crate::rules::batch5::s2187_test_framework_rules::TestFrameworkCollector;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::RuleScope;
use crate::support::callee_name;
use crate::support::span_text;
use crate::support::unparenthesized;
use oxc_ast::ast::CallExpression;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

/// Chai matcher methods counted by the `S6092` chain check.
const CHAI_MATCHER_METHODS: [&str; 10] = [
    "equal", "eql", "match", "include", "contain", "keys", "property", "lengthOf", "above", "below",
];

/// Walks `expect(x).to.equal(y)`-style callees down to their `expect` root,
/// collecting member links outermost-first across chained matcher calls.
fn deconstruct_expect_chain<'a>(
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

impl TestFrameworkCollector<'_, '_> {
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
}
