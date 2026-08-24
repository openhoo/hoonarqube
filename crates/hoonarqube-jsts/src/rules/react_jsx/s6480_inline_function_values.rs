use super::walker::ReactCollector;
use crate::support::RuleScope;
use oxc_ast::ast::Expression;
use oxc_ast::ast::JSXAttributeItem;
use oxc_ast::ast::JSXAttributeValue;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6480`: inline arrow or `.bind(...)` attribute values create a new
    /// function on every render.
    pub(crate) fn check_inline_function_values(&mut self, element: &JSXElement<'_>) {
        for item in &element.opening_element.attributes {
            let JSXAttributeItem::Attribute(attribute) = item else {
                continue;
            };
            let Some(JSXAttributeValue::ExpressionContainer(container)) = &attribute.value else {
                continue;
            };
            let inline = match container.expression.as_expression() {
                Some(Expression::ArrowFunctionExpression(_)) => true,
                Some(Expression::CallExpression(call)) => matches!(
                    &call.callee,
                    Expression::StaticMemberExpression(member) if member.property.name == "bind"
                ),
                _ => false,
            };
            if inline {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6480",
                    "Create this function outside of the render path; a fresh instance is created on every render.",
                    attribute.span(),
                );
            }
        }
    }
}
