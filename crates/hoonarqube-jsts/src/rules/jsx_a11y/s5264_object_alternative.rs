use super::walker::{
    A11yCollector, SubtreeFacts, jsx_element_tag, jsx_find_attribute, jsx_has_spread_attribute,
};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S5264`: object elements need a text alternative.
    pub(crate) fn check_object_alternative(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("object")
            || jsx_has_spread_attribute(&element.opening_element)
        {
            return;
        }
        let labeled = ["aria-label", "aria-labelledby", "title"]
            .iter()
            .any(|name| jsx_find_attribute(&element.opening_element, name).is_some());
        if labeled {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        if !facts.has_visible_text {
            self.sink.emit_span(
                RuleScope::Both,
                "S5264",
                "Provide a text alternative for this <object> element.",
                element.opening_element.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s5264_flags_objects_without_text_alternatives() {
        let bare = jsx_keys("const el = <object data=\"x.swf\"/>;\n");
        assert_eq!(count_key(&bare, "javascript:S5264"), 1);

        let empty = jsx_keys("const el = <object data=\"x.swf\"><span/></object>;\n");
        assert_eq!(count_key(&empty, "javascript:S5264"), 1);
    }

    #[test]
    fn s5264_accepts_fallback_text_and_labels() {
        let fallback = jsx_keys("const el = <object data=\"x.swf\">fallback</object>;\n");
        assert_eq!(count_key(&fallback, "javascript:S5264"), 0);

        let titled = jsx_keys("const el = <object data=\"x.swf\" title=\"movie\"/>;\n");
        assert_eq!(count_key(&titled, "javascript:S5264"), 0);

        let labelled_by =
            jsx_keys("const el = <object data=\"x.swf\" aria-labelledby=\"obj-label\"/>;\n");
        assert_eq!(count_key(&labelled_by, "javascript:S5264"), 0);
    }

    #[test]
    fn s5264_skips_spread_elements_and_other_tags() {
        let spread = jsx_keys("const el = <object {...props}/>;\n");
        assert_eq!(count_key(&spread, "javascript:S5264"), 0);

        let other_tag = jsx_keys("const el = <embed src=\"x.swf\"/>;\n");
        assert_eq!(count_key(&other_tag, "javascript:S5264"), 0);
    }
}
