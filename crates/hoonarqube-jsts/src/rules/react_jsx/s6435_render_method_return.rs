use super::walker::{ReactCollector, RenderReturnScanner, duplicated_key_name};
use crate::support::RuleScope;
use oxc_ast::ast::Class;
use oxc_ast::ast::ClassElement;
use oxc_ast::ast::MethodDefinitionKind;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6435`: class `render` methods must return JSX or null somewhere.
    pub(crate) fn check_render_method_return(&mut self, class: &Class<'_>) {
        for element in &class.body.body {
            let ClassElement::MethodDefinition(method) = element else {
                continue;
            };
            if duplicated_key_name(&method.key) != Some("render")
                || method.kind != MethodDefinitionKind::Method
            {
                continue;
            }
            let Some(body) = &method.value.body else {
                continue;
            };
            let mut scanner = RenderReturnScanner::default();
            scanner.visit_function_body(body);
            if !scanner.satisfied {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6435",
                    "Add a return statement returning JSX or null to this 'render' method.",
                    method.key.span(),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6435_flags_render_returning_non_jsx_value() {
        let findings = jsx_keys("class A {\n  render() {\n    return 42;\n  }\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6435"), 1);
    }

    #[test]
    fn s6435_allows_render_returning_null() {
        let findings = jsx_keys("class A {\n  render() {\n    return null;\n  }\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6435"), 0);
    }

    #[test]
    fn s6435_nested_function_return_satisfies_probe() {
        let findings = jsx_keys(
            "class A {\n  render() {\n    const helper = function () {\n      return null;\n    };\n  }\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6435"), 0);
    }
}
