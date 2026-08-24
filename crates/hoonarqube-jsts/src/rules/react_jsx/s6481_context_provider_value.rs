use super::walker::{ReactCollector, jsx_find_attribute};
use crate::support::RuleScope;
use oxc_ast::ast::Expression;
use oxc_ast::ast::JSXAttributeValue;
use oxc_ast::ast::JSXElement;
use oxc_ast::ast::JSXElementName;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6481`: freshly created object or array literals passed as
    /// `Context.Provider` values.
    ///
    /// Intentional CE divergence: the captured engine also fires on provably
    /// stable values such as hoisted module-level constants (oracle-js
    /// `s6481_good.jsx`), which already provide exactly the memoization the
    /// rule asks for. We restrict the finding to inline literals evaluated
    /// in place; identifiers (including module-level memoized values) pass.
    pub(crate) fn check_context_provider_value(&mut self, element: &JSXElement<'_>) {
        let JSXElementName::MemberExpression(member) = &element.opening_element.name else {
            return;
        };
        if member.property.name != "Provider" {
            return;
        }
        let Some(value_attribute) = jsx_find_attribute(&element.opening_element, "value") else {
            return;
        };
        let Some(JSXAttributeValue::ExpressionContainer(container)) = &value_attribute.value else {
            return;
        };
        if matches!(
            container.expression.as_expression(),
            Some(Expression::ObjectExpression(_) | Expression::ArrayExpression(_))
        ) {
            self.sink.emit_span(
                RuleScope::Both,
                "S6481",
                "Pass a memoized 'value' instead of a fresh object or array literal.",
                value_attribute.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6481_flags_inline_object_provider_value() {
        let findings = jsx_keys("const el = <Ctx.Provider value={{a: 1}}></Ctx.Provider>;\n");
        assert_eq!(count_key(&findings, "javascript:S6481"), 1);
    }

    #[test]
    fn s6481_flags_inline_array_provider_value() {
        let findings = jsx_keys("const el = <Ctx.Provider value={[]}></Ctx.Provider>;\n");
        assert_eq!(count_key(&findings, "javascript:S6481"), 1);
    }

    #[test]
    fn s6481_allows_memoized_provider_value() {
        let findings = jsx_keys("const el = <Ctx.Provider value={memo}></Ctx.Provider>;\n");
        assert_eq!(count_key(&findings, "javascript:S6481"), 0);
    }

    #[test]
    fn s6481_ignores_non_provider_member_elements() {
        let findings = jsx_keys("const el = <Ctx.Consumer value={{a: 1}}></Ctx.Consumer>;\n");
        assert_eq!(count_key(&findings, "javascript:S6481"), 0);
    }

    #[test]
    fn s6481_allows_hoisted_module_level_memo_const() {
        // CE-divergence pin: stable module-level references stay clean even
        // though the captured engine overfires on them.
        let findings = jsx_keys(
            "const memo = {a: 1};\nconst el = <Ctx.Provider value={memo}></Ctx.Provider>;\n",
        );
        assert_eq!(count_key(&findings, "javascript:S6481"), 0);
    }
}
