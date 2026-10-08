use super::walker::ReactCollector;
use crate::support::RuleScope;
use oxc_ast::ast::Expression;
use oxc_span::Span;

// Generated per-rule checks (moved out of traversal overrides).
impl ReactCollector<'_> {
    /// The reference rule reports property access on `this`, not bare receiver values.
    pub(crate) fn check_s6757_member_expression(&mut self, object: &Expression<'_>, span: Span) {
        if matches!(
            crate::support::unparenthesized(object),
            Expression::ThisExpression(_)
        ) && self.method_guard == 0
            && self.class_depth == 0
            && self.component_stack.last() == Some(&true)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6757",
                "Stateless functional components should not use `this`",
                span,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6757_flags_this_inside_function_component() {
        let findings =
            jsx_keys("function C() {\n  console.log(this.value);\n  return <span></span>;\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6757"), 1);
    }

    #[test]
    fn s6757_bare_this_values_and_descriptor_receivers_are_clean() {
        let component = jsx_keys("function Direct() { console.log(this); return <div/>; }");
        assert_eq!(count_key(&component, "javascript:S6757"), 0);
        let descriptor = js_keys(
            "function defineBound(proto, key, fn) { Object.defineProperty(proto, key, { get() { return this == null ? fn : own(this, key, fn.bind(this)); }, set(value) { own(this, key, value); } }); }",
        );
        assert_eq!(count_key(&descriptor, "javascript:S6757"), 0);
    }

    #[test]
    fn s6757_member_primary_and_message_match_reference() {
        let source = "function C() { return <div>{this.value}</div>; }";
        let report = crate::analyze(
            std::path::PathBuf::from("test.jsx"),
            source,
            crate::JstsLanguage::JavaScript,
            &no_header_options(),
        );
        let hits: Vec<_> = report
            .issues
            .iter()
            .filter(|issue| issue.rule_key == "javascript:S6757")
            .collect();
        assert_eq!(hits.len(), 1);
        let start = u32::try_from(source.find("this.value").unwrap()).unwrap();
        assert_eq!(
            hits[0].range,
            crate::support::LineIndex::new(source).range(oxc_span::Span::new(start, start + 10))
        );
        assert_eq!(
            hits[0].message,
            "Stateless functional components should not use `this`"
        );
    }

    #[test]
    fn s6757_allows_this_inside_class_method() {
        let findings = js_keys("class Widget {\n  save() {\n    this.x();\n  }\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6757"), 0);
    }

    #[test]
    fn s6757_ignores_this_in_non_component_function() {
        let findings = js_keys("function helper() {\n  console.log(this);\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6757"), 0);
    }
}
