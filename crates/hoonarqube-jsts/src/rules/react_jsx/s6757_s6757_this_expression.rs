use super::walker::ReactCollector;
use crate::support::RuleScope;
use oxc_span::GetSpan;

// Generated per-rule checks (moved out of traversal overrides).
impl ReactCollector<'_> {
    /// `S6757` logic extracted from `visit_this_expression`.
    pub(crate) fn check_s6757_this_expression(&mut self, it: &oxc_ast::ast::ThisExpression) {
        if self.method_guard == 0
            && self.class_depth == 0
            && self.component_stack.last() == Some(&true)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6757",
                "'this' is undefined inside a functional component; capture the needed values instead.",
                it.span(),
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
            jsx_keys("function C() {\n  console.log(this);\n  return <span></span>;\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6757"), 1);
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
