use super::collectors_hotspots::ASSERTION_MARKERS;
use crate::engine::scope_model::function_body_span;
use crate::engine::scope_model::function_parameters;
use crate::engine::scope_model::parameter_names;
use crate::rules::batch5::s2187_test_framework_rules::TestFrameworkCollector;
use crate::rules::expression::s1528_constructor_calls::argument_expression;
use crate::support::RuleScope;
use crate::support::callee_name;
use oxc_ast::ast::CallExpression;

/// Whether trimmed text still holds statements after the last `done()` call.
fn statements_follow_done(text: &str) -> bool {
    let Some(position) = text.rfind("done()") else {
        return false;
    };
    let remainder = text[position + "done()".len()..].trim_matches(|character: char| {
        character.is_whitespace() || character == '}' || character == ';'
    });
    !remainder.is_empty()
}

impl TestFrameworkCollector<'_, '_> {
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
}
