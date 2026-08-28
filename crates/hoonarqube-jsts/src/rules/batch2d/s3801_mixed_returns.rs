use super::collectors::{FunctionMetricsCollector, ReturnMixScanner};
use crate::rules::shared::statement_ends_with_jump;
use crate::support::RuleScope;
use oxc_ast::ast::FunctionBody;
use oxc_ast_visit::Visit;
use oxc_span::Span;

impl FunctionMetricsCollector<'_> {
    /// `S3801`: a function mixing valued and bare returns, or returning values
    /// while also falling off the end, is flagged at the function itself.
    pub(crate) fn check_mixed_returns(&mut self, body: &FunctionBody<'_>, anchor: Span) {
        let mut scanner = ReturnMixScanner::default();
        scanner.visit_function_body(body);
        let falls_off_end = !body
            .statements
            .last()
            .is_some_and(|last| statement_ends_with_jump(last));
        if !scanner.valued_spans.is_empty() && !scanner.bare_spans.is_empty() {
            self.sink.emit_span(
                RuleScope::Both,
                "S3801",
                "Refactor this function to use \"return\" consistently.",
                anchor,
            );
        } else if !scanner.valued_spans.is_empty() && falls_off_end {
            self.sink.emit_span(
                RuleScope::Both,
                "S3801",
                "Make this function consistently return a value.",
                anchor,
            );
        }
    }
}
