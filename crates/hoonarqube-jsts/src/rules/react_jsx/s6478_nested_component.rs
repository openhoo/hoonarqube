use super::walker::ReactCollector;
use crate::support::RuleScope;
use oxc_span::Span;

impl ReactCollector<'_> {
    /// `S6478`: components defined inside other components.
    pub(crate) fn check_nested_component(
        &mut self,
        returns_jsx: bool,
        name_span: Option<Span>,
        fallback_span: Span,
    ) {
        if !returns_jsx
            || !self.component_stack.iter().any(|&component| component)
            || self.method_guard > 0
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6478",
            "Define this component outside of its parent component.",
            name_span.unwrap_or(fallback_span),
        );
    }
}
