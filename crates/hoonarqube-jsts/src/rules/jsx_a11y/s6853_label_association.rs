use super::walker::{
    A11yCollector, SubtreeFacts, jsx_element_tag, jsx_find_attribute, jsx_has_spread_attribute,
};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6853`: labels need text and a control association.
    pub(crate) fn check_label_association(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("label")
            || jsx_has_spread_attribute(&element.opening_element)
        {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        let labeled = ["aria-label", "aria-labelledby"]
            .iter()
            .any(|name| jsx_find_attribute(&element.opening_element, name).is_some());
        let associated = jsx_find_attribute(&element.opening_element, "htmlFor").is_some()
            || facts.labelable_controls > 0;
        if (!facts.has_visible_text && !labeled) || !associated {
            self.sink.emit_span(
                RuleScope::Both,
                "S6853",
                "Associate this <label> with a form control and give it text content.",
                element.opening_element.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6853_flags_labels_missing_text_or_control() {
        let orphan = jsx_keys("const el = <label>Surname</label>;\n");
        assert_eq!(count_key(&orphan, "javascript:S6853"), 1);

        let empty_for = jsx_keys("const el = <label htmlFor=\"q\"/>;\n");
        assert_eq!(count_key(&empty_for, "javascript:S6853"), 1);
    }

    #[test]
    fn s6853_accepts_associated_and_labelled_forms() {
        let for_attribute = jsx_keys("const el = <label htmlFor=\"q\">Query</label>;\n");
        assert_eq!(count_key(&for_attribute, "javascript:S6853"), 0);

        let nested = jsx_keys("const el = <label>Name<input/></label>;\n");
        assert_eq!(count_key(&nested, "javascript:S6853"), 0);

        let aria_labelled = jsx_keys("const el = <label aria-label=\"Name\"><input/></label>;\n");
        assert_eq!(count_key(&aria_labelled, "javascript:S6853"), 0);
    }

    #[test]
    fn s6853_skips_spread_elements_and_other_tags() {
        let spread = jsx_keys("const el = <label {...props}/>;\n");
        assert_eq!(count_key(&spread, "javascript:S6853"), 0);

        let other_tag = jsx_keys("const el = <div>Surname</div>;\n");
        assert_eq!(count_key(&other_tag, "javascript:S6853"), 0);
    }
}
