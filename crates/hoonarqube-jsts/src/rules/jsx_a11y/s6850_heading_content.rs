use super::walker::{A11yCollector, SubtreeFacts, jsx_element_tag, jsx_find_attribute};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6850`: headings must have text content or a label.
    pub(crate) fn check_heading_content(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !matches!(tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6") {
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
                "S6850",
                "This heading has no text content.",
                element.opening_element.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6850_flags_headings_without_text_or_labels() {
        let bare = jsx_keys("const el = <h2/>;\n");
        assert_eq!(count_key(&bare, "javascript:S6850"), 1);

        let icon_only = jsx_keys("const el = <h4><span/></h4>;\n");
        assert_eq!(count_key(&icon_only, "javascript:S6850"), 1);
    }

    #[test]
    fn s6850_accepts_text_and_labelled_headings() {
        let textual = jsx_keys("const el = <h1>Release notes</h1>;\n");
        assert_eq!(count_key(&textual, "javascript:S6850"), 0);

        let labelled_by = jsx_keys("const el = <h3 aria-labelledby=\"section-title\"/>;\n");
        assert_eq!(count_key(&labelled_by, "javascript:S6850"), 0);

        let titled = jsx_keys("const el = <h6 title=\"Footer\"/>;\n");
        assert_eq!(count_key(&titled, "javascript:S6850"), 0);
    }

    #[test]
    fn s6850_accepts_expression_children() {
        let identifier = jsx_keys("const el = <h2>{title}</h2>;\n");
        assert_eq!(count_key(&identifier, "javascript:S6850"), 0);

        let member = jsx_keys("const el = <h2>{user.name}</h2>;\n");
        assert_eq!(count_key(&member, "javascript:S6850"), 0);

        let nested = jsx_keys("const el = <h3><b>{label}</b></h3>;\n");
        assert_eq!(count_key(&nested, "javascript:S6850"), 0);
    }

    #[test]
    fn s6850_flags_non_rendering_expression_children() {
        let empty_container = jsx_keys("const el = <h2>{/* nothing */}</h2>;\n");
        assert_eq!(count_key(&empty_container, "javascript:S6850"), 1);

        let undefined = jsx_keys("const el = <h2>{undefined}</h2>;\n");
        assert_eq!(count_key(&undefined, "javascript:S6850"), 1);

        // Attribute expressions are not heading content.
        let attribute_only = jsx_keys("const el = <h2 data-note={note}/>;\n");
        assert_eq!(count_key(&attribute_only, "javascript:S6850"), 1);
    }

    #[test]
    fn s6850_ignores_non_heading_elements() {
        let paragraph = jsx_keys("const el = <p/>;\n");
        assert_eq!(count_key(&paragraph, "javascript:S6850"), 0);
    }
}
