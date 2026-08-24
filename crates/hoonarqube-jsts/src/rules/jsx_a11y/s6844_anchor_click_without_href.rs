use super::walker::{A11yCollector, jsx_element_tag, jsx_find_attribute, jsx_has_spread_attribute};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6844`: click handlers on anchors without `href`.
    pub(crate) fn check_anchor_click_without_href(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("a")
            || jsx_has_spread_attribute(&element.opening_element)
            || jsx_find_attribute(&element.opening_element, "href").is_some()
        {
            return;
        }
        if jsx_find_attribute(&element.opening_element, "onClick").is_some() {
            self.sink.emit_span(
                RuleScope::Both,
                "S6844",
                "Add an 'href' to this <a> or use a <button> for this action.",
                element.opening_element.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6844_flags_anchor_click_handlers_missing_href() {
        let click_only = jsx_keys("const el = <a onClick={openMenu}>Menu</a>;\n");
        assert_eq!(count_key(&click_only, "javascript:S6844"), 1);
    }

    #[test]
    fn s6844_accepts_anchors_with_href_and_plain_buttons() {
        let linked = jsx_keys("const el = <a href=\"/menu\" onClick={openMenu}>Menu</a>;\n");
        assert_eq!(count_key(&linked, "javascript:S6844"), 0);

        let button = jsx_keys("const el = <button onClick={openMenu}>Menu</button>;\n");
        assert_eq!(count_key(&button, "javascript:S6844"), 0);
    }

    #[test]
    fn s6844_requires_click_handler_and_skips_spread_anchors() {
        let no_handler = jsx_keys("const el = <a>Menu</a>;\n");
        assert_eq!(count_key(&no_handler, "javascript:S6844"), 0);

        let spread = jsx_keys("const el = <a {...props} onClick={openMenu}>Menu</a>;\n");
        assert_eq!(count_key(&spread, "javascript:S6844"), 0);
    }
}
