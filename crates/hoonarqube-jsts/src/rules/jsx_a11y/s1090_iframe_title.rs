use super::walker::{A11yCollector, jsx_element_tag, jsx_find_attribute, jsx_has_spread_attribute};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S1090`: iframes need titles.
    pub(crate) fn check_iframe_title(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("iframe")
            || jsx_has_spread_attribute(&element.opening_element)
            || jsx_find_attribute(&element.opening_element, "title").is_some()
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S1090",
            "Add a 'title' attribute to this <iframe>.",
            element.opening_element.span(),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s1090_flags_iframes_missing_title() {
        let bare = jsx_keys("const el = <iframe src=\"https://example.com\"/>;\n");
        assert_eq!(count_key(&bare, "javascript:S1090"), 1);
    }

    #[test]
    fn s1090_accepts_titled_iframes_even_with_empty_title() {
        let titled = jsx_keys("const el = <iframe src=\"https://example.com\" title=\"Map\"/>;\n");
        assert_eq!(count_key(&titled, "javascript:S1090"), 0);

        let empty_title = jsx_keys("const el = <iframe title=\"\"/>;\n");
        assert_eq!(count_key(&empty_title, "javascript:S1090"), 0);
    }

    #[test]
    fn s1090_skips_iframes_with_spread_attributes() {
        let spread = jsx_keys("const el = <iframe {...props}/>;\n");
        assert_eq!(count_key(&spread, "javascript:S1090"), 0);
    }
}
