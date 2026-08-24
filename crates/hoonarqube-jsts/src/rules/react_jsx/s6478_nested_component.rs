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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6478_flags_component_defined_inside_component() {
        let findings = jsx_keys(
            "function Outer() {\n  function Inner() {\n    return <span></span>;\n  }\n  return <Inner></Inner>;\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6478"), 1);
    }

    #[test]
    fn s6478_allows_top_level_arrow_components() {
        let findings = jsx_keys("const A = () => <a></a>;\nconst B = () => <b></b>;\n");
        assert_eq!(count_key(&findings, "javascript:S6478"), 0);
    }

    #[test]
    fn s6478_ignores_non_component_inner_function() {
        let findings = jsx_keys(
            "function Outer() {\n  function helper() {\n    return 1;\n  }\n  return <span></span>;\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6478"), 0);
    }
}
