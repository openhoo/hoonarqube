use super::walker::{
    A11yCollector, attribute_static_value, jsx_element_tag, jsx_find_attribute,
    jsx_has_spread_attribute, jsx_tag_is_intrinsic,
};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S1077`: images, areas, objects, and image inputs need alt text.
    pub(crate) fn check_alt_text(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag) {
            return;
        }
        let needs_alt = match tag {
            "img" | "area" | "object" => true,
            "input" => {
                jsx_find_attribute(&element.opening_element, "type")
                    .and_then(attribute_static_value)
                    == Some("image")
            }
            _ => false,
        };
        if !needs_alt || jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        if jsx_find_attribute(&element.opening_element, "alt").is_none() {
            let message = format!("Add an 'alt' attribute to this <{tag}> element.");
            self.sink.emit_span(
                RuleScope::Both,
                "S1077",
                &message,
                element.opening_element.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s1077_flags_area_and_object_without_alt() {
        let area = jsx_keys("const el = <area shape=\"rect\"/>;\n");
        assert_eq!(count_key(&area, "javascript:S1077"), 1);

        let object = jsx_keys("const el = <object data=\"x.swf\"/>;\n");
        assert_eq!(count_key(&object, "javascript:S1077"), 1);
    }

    #[test]
    fn s1077_only_requires_alt_on_image_inputs() {
        let image_input = jsx_keys("const el = <input type=\"image\" src=\"go.png\"/>;\n");
        assert_eq!(count_key(&image_input, "javascript:S1077"), 1);

        let checkbox_input = jsx_keys("const el = <input type=\"checkbox\"/>;\n");
        assert_eq!(count_key(&checkbox_input, "javascript:S1077"), 0);

        let image_with_alt =
            jsx_keys("const el = <input type=\"image\" alt=\"Submit search\"/>;\n");
        assert_eq!(count_key(&image_with_alt, "javascript:S1077"), 0);
    }

    #[test]
    fn s1077_accepts_empty_alt_and_skips_spread_elements() {
        let decorative = jsx_keys("const el = <img src=\"divider.gif\" alt=\"\"/>;\n");
        assert_eq!(count_key(&decorative, "javascript:S1077"), 0);

        let spread = jsx_keys("const el = <img {...props}/>;\n");
        assert_eq!(count_key(&spread, "javascript:S1077"), 0);
    }
}
