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
