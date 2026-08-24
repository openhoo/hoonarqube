use super::walker::{
    A11yCollector, attribute_integer_value, attribute_static_value, is_interactive_element,
    jsx_element_tag, jsx_find_attribute, jsx_has_spread_attribute, jsx_tag_is_intrinsic,
};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6825`: focusable elements cannot be hidden from assistive tech.
    pub(crate) fn check_aria_hidden_focusable(&mut self, element: &JSXElement<'_>) {
        if jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        let Some(hidden_attribute) = jsx_find_attribute(&element.opening_element, "aria-hidden")
        else {
            return;
        };
        if attribute_static_value(hidden_attribute) != Some("true") {
            return;
        }
        let intrinsically_focusable = match jsx_element_tag(&element.opening_element.name) {
            Some(tag) if jsx_tag_is_intrinsic(tag) => {
                is_interactive_element(tag, &element.opening_element)
            }
            _ => false,
        };
        let tabbable = ["tabIndex", "tabindex"].iter().any(|name| {
            jsx_find_attribute(&element.opening_element, name)
                .and_then(attribute_integer_value)
                .is_some_and(|value| value >= 0)
        });
        if intrinsically_focusable || tabbable {
            self.sink.emit_span(
                RuleScope::Both,
                "S6825",
                "Do not hide this focusable element with 'aria-hidden=\"true\"'.",
                hidden_attribute.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6825_flags_hidden_selects_and_tabbable_elements() {
        let hidden_select = jsx_keys("const el = <select aria-hidden=\"true\"/>;\n");
        assert_eq!(count_key(&hidden_select, "javascript:S6825"), 1);

        let tabbable = jsx_keys("const el = <div aria-hidden=\"true\" tabindex=\"0\"/>;\n");
        assert_eq!(count_key(&tabbable, "javascript:S6825"), 1);
    }

    #[test]
    fn s6825_accepts_false_values_static_elements_and_negative_indices() {
        let not_hidden = jsx_keys("const el = <button aria-hidden=\"false\">Go</button>;\n");
        assert_eq!(count_key(&not_hidden, "javascript:S6825"), 0);

        let static_element = jsx_keys("const el = <p aria-hidden=\"true\">text</p>;\n");
        assert_eq!(count_key(&static_element, "javascript:S6825"), 0);

        let negative = jsx_keys("const el = <div aria-hidden=\"true\" tabIndex={-1}/>;\n");
        assert_eq!(count_key(&negative, "javascript:S6825"), 0);
    }

    #[test]
    fn s6825_skips_spread_elements() {
        let spread = jsx_keys("const el = <button {...rest} aria-hidden=\"true\"/>;\n");
        assert_eq!(count_key(&spread, "javascript:S6825"), 0);
    }
}
