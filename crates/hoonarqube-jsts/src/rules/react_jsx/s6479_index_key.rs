use super::walker::{ReactCollector, jsx_find_attribute};
use crate::support::RuleScope;
use oxc_ast::ast::Expression;
use oxc_ast::ast::JSXAttributeValue;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6479`: `key={index}` where `index` is the surrounding `.map()`
    /// callback's second parameter.
    pub(crate) fn check_index_key(&mut self, element: &JSXElement<'_>) {
        let Some(index_param) = self
            .map_frames
            .last()
            .and_then(|frame| frame.index_param.clone())
        else {
            return;
        };
        let Some(key_attribute) = jsx_find_attribute(&element.opening_element, "key") else {
            return;
        };
        let Some(JSXAttributeValue::ExpressionContainer(container)) = &key_attribute.value else {
            return;
        };
        let is_index_key = matches!(
            container.expression.as_expression(),
            Some(Expression::Identifier(reference)) if reference.name == index_param.as_str()
        );
        if is_index_key {
            self.sink.emit_span(
                RuleScope::Both,
                "S6479",
                "Avoid using the array index as the 'key'; use a stable identifier instead.",
                key_attribute.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6479_flags_index_as_key_in_map_callback() {
        let findings = jsx_keys("items.map((item, index) => <li key={index}></li>);\n");
        assert_eq!(count_key(&findings, "javascript:S6479"), 1);
    }

    #[test]
    fn s6479_allows_stable_key_in_map_callback() {
        let findings = jsx_keys("items.map((item, index) => <li key={item.id}></li>);\n");
        assert_eq!(count_key(&findings, "javascript:S6479"), 0);
    }

    #[test]
    fn s6479_index_outside_key_misses_but_missing_key_reports_s6477() {
        let findings = jsx_keys("items.map((item, index) => <li title={index}></li>);\n");
        assert_eq!(count_key(&findings, "javascript:S6479"), 0);
        assert_eq!(count_key(&findings, "javascript:S6477"), 1);
    }
}
