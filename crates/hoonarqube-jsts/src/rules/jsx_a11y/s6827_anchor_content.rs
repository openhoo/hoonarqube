use super::walker::{A11yCollector, SubtreeFacts, jsx_element_tag, jsx_find_attribute};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6827`: anchors without `href` still need accessible text.
    pub(crate) fn check_anchor_content(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("a")
            || jsx_find_attribute(&element.opening_element, "href").is_some()
        {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        if !facts.has_visible_text {
            self.sink.emit_span(
                RuleScope::Both,
                "S6827",
                "Give this <a> an 'href' or accessible text content.",
                element.opening_element.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6827_flags_anchors_without_accessible_content() {
        let bare = jsx_keys("const el = <a/>;\n");
        assert_eq!(count_key(&bare, "javascript:S6827"), 1);

        let label_only = jsx_keys("const el = <a aria-label=\"Open docs\"/>;\n");
        assert_eq!(count_key(&label_only, "javascript:S6827"), 1);
    }

    #[test]
    fn s6827_accepts_linked_or_textual_anchors() {
        let linked = jsx_keys("const el = <a href=\"/docs\"/>;\n");
        assert_eq!(count_key(&linked, "javascript:S6827"), 0);

        let textual = jsx_keys("const el = <a>Documentation</a>;\n");
        assert_eq!(count_key(&textual, "javascript:S6827"), 0);

        let other_tag = jsx_keys("const el = <abbr>HTML</abbr>;\n");
        assert_eq!(count_key(&other_tag, "javascript:S6827"), 0);
    }
}
