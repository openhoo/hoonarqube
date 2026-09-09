use super::walker::ReactCollector;
use crate::support::RuleScope;
use oxc_span::Span;

impl ReactCollector<'_> {
    /// `S6478`: components defined inside other components.
    pub(crate) fn check_nested_component(
        &mut self,
        returns_jsx: bool,
        _name_span: Option<Span>,
        fallback_span: Span,
    ) {
        if !returns_jsx
            || !self.component_stack.iter().any(|&component| component)
            || self.method_guard > 0
        {
            return;
        }
        let parent = self
            .component_names
            .iter()
            .rev()
            .find_map(Option::as_deref)
            .unwrap_or("parent");
        self.sink.emit_span(
            RuleScope::Both,
            "S6478",
            &format!(
                "Do not define components during render. React will see a new component type on every render and destroy the entire subtree’s DOM nodes and state. Instead, move this component definition out of the parent component “{parent}” and pass data as props."
            ),
            fallback_span,
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;
    fn tsx_keys(source: &str) -> Vec<(String, u32)> {
        report_keys(&analyze(
            PathBuf::from("test.tsx"),
            source,
            JstsLanguage::TypeScript,
            &AnalyzerOptions::default(),
        ))
    }

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

    #[test]
    fn s6478_flags_component_functions_in_object_properties() {
        let local = jsx_keys(
            "function Panel() {\n  const renderers = { Item: () => <b>ok</b> };\n  return <Widget renderers={renderers}/>;\n}\n",
        );
        assert_eq!(count_key(&local, "javascript:S6478"), 1);

        let inline = jsx_keys(
            "function Panel() {\n  return <Widget values={{ Item: () => <b>ok</b> }}/>;\n}\n",
        );
        assert_eq!(count_key(&inline, "javascript:S6478"), 1);
    }

    #[test]
    fn s6478_flags_function_expression_components_in_object_properties() {
        let local = jsx_keys(
            "function Panel() {\n  const renderers = { Item: function Item() { return <b>ok</b>; } };\n  return <Widget renderers={renderers}/>;\n}\n",
        );
        assert_eq!(count_key(&local, "javascript:S6478"), 1);

        let inline = jsx_keys(
            "function Panel() {\n  return <Widget values={{ Item: function Item() { return <b>ok</b>; } }}/>;\n}\n",
        );
        assert_eq!(count_key(&inline, "javascript:S6478"), 1);
    }

    #[test]
    fn s6478_reports_the_object_property_function_span() {
        let source = "function Panel() {\n  const renderers = { Item: () => <b>ok</b> };\n  return <Widget renderers={renderers}/>;\n}\n";
        let issue = jsx(source)
            .issues
            .into_iter()
            .find(|issue| issue.rule_key == "javascript:S6478")
            .expect("object-property component should be reported");
        assert_eq!(issue.range.start.line, 2);
        assert_eq!(issue.range.start.column, 28);
    }

    #[test]
    fn s6478_allows_module_level_and_non_component_object_properties() {
        let module_level =
            jsx_keys("const renderers = { Item: () => <b>ok</b> };\nconst el = <Widget/>;\n");
        assert_eq!(count_key(&module_level, "javascript:S6478"), 0);

        let non_component = jsx_keys(
            "function Panel() {\n  const renderers = { Item: () => 1 };\n  return <Widget renderers={renderers}/>;\n}\n",
        );
        assert_eq!(count_key(&non_component, "javascript:S6478"), 0);
    }

    #[test]
    fn s6478_allows_react_intl_formatting_callbacks() {
        let values = jsx_keys(
            "function Panel() {\n  return <FormattedMessage values={{ Item: chunks => <b>{chunks}</b> }}/>;\n}\n",
        );
        assert_eq!(count_key(&values, "javascript:S6478"), 0);

        let format_message = jsx_keys(
            "function Panel() {\n  return intl.formatMessage(descriptor, { Item: chunks => <b>{chunks}</b> });\n}\n",
        );
        assert_eq!(count_key(&format_message, "javascript:S6478"), 0);
    }

    #[test]
    fn s6478_flags_object_property_components_in_typescript_jsx() {
        let local = tsx_keys(
            "function Panel() {\n  const renderers = { Item: () => <b>ok</b> };\n  return <Widget renderers={renderers}/>;\n}\n",
        );
        assert_eq!(count_key(&local, "typescript:S6478"), 1);

        let inline = tsx_keys(
            "function Panel() {\n  return <Widget values={{ Item: () => <b>ok</b> }}/>;\n}\n",
        );
        assert_eq!(count_key(&inline, "typescript:S6478"), 1);
    }

    #[test]
    fn s6478_preserves_identifier_render_property_exceptions_but_flags_quoted_and_ordinary() {
        let render_property = jsx_keys(
            "function Panel() {\n  const renderers = { renderItem: () => <b>ok</b> };\n  return <Widget renderers={renderers}/>;\n}\n",
        );
        assert_eq!(count_key(&render_property, "javascript:S6478"), 0);

        let quoted_property = jsx_keys(
            "function Panel() {\n  const renderers = { 'renderFooter': function Footer() { return <b>ok</b>; } };\n  return <Widget renderers={renderers}/>;\n}\n",
        );
        assert_eq!(count_key(&quoted_property, "javascript:S6478"), 1);

        let ordinary_property = jsx_keys(
            "function Panel() {\n  const renderers = { Item: () => <b>ok</b> };\n  return <Widget renderers={renderers}/>;\n}\n",
        );
        assert_eq!(count_key(&ordinary_property, "javascript:S6478"), 1);
    }

    #[test]
    fn s6478_flags_exported_and_default_component_forms() {
        let findings = jsx_keys(
            "export function Outer() {\n  function Inner() { return <span/>; }\n  return <Inner/>;\n}\nexport default function Another() {\n  const Child = () => <span/>;\n  return <Child/>;\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6478"), 2);

        let default_arrow = jsx_keys(
            "export default () => {\n  const Child = () => <span/>;\n  return <Child/>;\n};\n",
        );
        assert_eq!(count_key(&default_arrow, "javascript:S6478"), 1);
    }
}
