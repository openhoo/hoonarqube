use super::walker::ReactCollector;
use crate::support::RuleScope;
use oxc_ast::ast::JSXChild;
use oxc_ast::ast::JSXFragment;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    pub(crate) fn check_single_child_fragment(&mut self, fragment: &JSXFragment<'_>) {
        let single_child = matches!(
            fragment.children.as_slice(),
            [JSXChild::Element(_) | JSXChild::ExpressionContainer(_)]
        );
        if single_child {
            self.sink.emit_span(
                RuleScope::Both,
                "S6749",
                "Remove this unnecessary fragment; it wraps a single child.",
                fragment.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6749_flags_fragment_wrapping_single_element() {
        let findings = jsx_keys("const el = (<><span></span></>);\n");
        assert_eq!(count_key(&findings, "javascript:S6749"), 1);
    }

    #[test]
    fn s6749_allows_fragment_with_two_children() {
        let findings = jsx_keys("const el = (<><span></span><b></b></>);\n");
        assert_eq!(count_key(&findings, "javascript:S6749"), 0);
    }

    #[test]
    fn s6749_flags_fragment_wrapping_single_expression() {
        let findings = jsx_keys("let item = 1;\nconst el = (<>{item}</>);\n");
        assert_eq!(count_key(&findings, "javascript:S6749"), 1);
    }
}
