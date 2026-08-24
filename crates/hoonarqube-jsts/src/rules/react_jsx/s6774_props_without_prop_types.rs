use super::walker::{ReactCollector, ThisPropsScanner, duplicated_key_name};
use crate::support::RuleScope;
use oxc_ast::ast::Class;
use oxc_ast::ast::ClassElement;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6774`: class components touching `this.props` without declared
    /// `propTypes` (JavaScript files only).
    pub(crate) fn check_props_without_prop_types(&mut self, class: &Class<'_>) {
        let declares_prop_types = class.body.body.iter().any(|element| {
            let ClassElement::PropertyDefinition(definition) = element else {
                return false;
            };
            definition.r#static && duplicated_key_name(&definition.key) == Some("propTypes")
        });
        if declares_prop_types {
            return;
        }
        let mut scanner = ThisPropsScanner::default();
        scanner.visit_class(class);
        if scanner.found {
            self.sink.emit_span(
                RuleScope::JsOnly,
                "S6774",
                "Declare 'propTypes' for this class component or migrate its props to types.",
                class.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6774_flags_this_props_without_declared_prop_types() {
        let findings = js_keys("class A {\n  m() {\n    return this.props.x;\n  }\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6774"), 1);
    }

    #[test]
    fn s6774_allows_class_with_static_prop_types() {
        let findings = js_keys(
            "class A {\n  static propTypes = {};\n  m() {\n    return this.props.x;\n  }\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6774"), 0);
    }

    #[test]
    fn s6774_is_javascript_only() {
        let findings = ts_keys("class A {\n  m() {\n    return this.props.x;\n  }\n}\n");
        assert_eq!(count_key(&findings, "typescript:S6774"), 0);
    }
}
