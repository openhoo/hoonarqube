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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6438_flags_empty_expression_container() {
        let findings = jsx_keys("const el = <span>{}</span>;\n");
        assert_eq!(count_key(&findings, "javascript:S6438"), 1);
    }

    #[test]
    fn s6438_allows_comment_only_container() {
        let findings = jsx_keys("const el = <div>{/* note */}</div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6438"), 0);
    }

    #[test]
    fn s6438_flags_each_empty_container_in_sequence() {
        let findings = jsx_keys("const el = <div>{}{}</div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6438"), 2);
    }
}
