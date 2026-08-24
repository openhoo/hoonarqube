use super::walker::ReactCollector;
use crate::support::RuleScope;
use crate::support::span_text_contains;
use oxc_ast::ast::JSXExpression;
use oxc_ast::ast::JSXExpressionContainer;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6438`: empty expression containers whose comment content was
    /// dropped by the lexer.
    pub(crate) fn check_empty_container(&mut self, container: &JSXExpressionContainer<'_>) {
        if !matches!(&container.expression, JSXExpression::EmptyExpression(_)) {
            return;
        }
        let span = container.span();
        if span_text_contains(self.source, span, "/*")
            || span_text_contains(self.source, span, "//")
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6438",
            "Remove this empty JSX expression container.",
            span,
        );
    }
}
