use super::walker::{ReactCollector, duplicated_key_name};
use crate::support::RuleScope;
use oxc_ast::ast::Class;
use oxc_ast::ast::ClassElement;
use oxc_ast::ast::Expression;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6763`: `shouldComponentUpdate` is pointless on `PureComponent`.
    pub(crate) fn check_pure_component_update(&mut self, class: &Class<'_>) {
        let Some(heritage) = &class.heritage else {
            return;
        };
        let pure_base = match &heritage.expression {
            Expression::Identifier(identifier) => identifier.name.ends_with("PureComponent"),
            Expression::StaticMemberExpression(member) => member.property.name == "PureComponent",
            _ => false,
        };
        if !pure_base {
            return;
        }
        for element in &class.body.body {
            let ClassElement::MethodDefinition(method) = element else {
                continue;
            };
            if duplicated_key_name(&method.key) != Some("shouldComponentUpdate") {
                continue;
            }
            self.sink.emit_span(
                RuleScope::Both,
                "S6763",
                "'shouldComponentUpdate' is useless on a PureComponent subclass; remove it.",
                method.key.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6763_flags_should_component_update_on_pure_component() {
        let findings = js_keys(
            "class A extends PureComponent {\n  shouldComponentUpdate() {}\n  render() {\n    return null;\n  }\n}\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6763"), 1);
    }

    #[test]
    fn s6763_allows_should_component_update_on_plain_component() {
        let findings = js_keys("class A extends Component {\n  shouldComponentUpdate() {}\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6763"), 0);
    }

    #[test]
    fn s6763_flags_member_expression_pure_component_base() {
        let findings =
            js_keys("class A extends React.PureComponent {\n  shouldComponentUpdate() {}\n}\n");
        assert_eq!(count_key(&findings, "javascript:S6763"), 1);
    }
}
