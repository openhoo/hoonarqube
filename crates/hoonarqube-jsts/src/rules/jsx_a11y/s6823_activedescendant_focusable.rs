use super::walker::{A11yCollector, jsx_find_attribute, jsx_has_spread_attribute};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6823`: `aria-activedescendant` requires a tab index.
    pub(crate) fn check_activedescendant_focusable(&mut self, element: &JSXElement<'_>) {
        if jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        let Some(active_attribute) =
            jsx_find_attribute(&element.opening_element, "aria-activedescendant")
        else {
            return;
        };
        if ["tabIndex", "tabindex"]
            .iter()
            .any(|name| jsx_find_attribute(&element.opening_element, name).is_some())
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6823",
            "Elements with 'aria-activedescendant' must carry 'tabIndex'.",
            active_attribute.span(),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6823_flags_activedescendant_without_tab_index() {
        let missing =
            jsx_keys("const el = <div role=\"listbox\" aria-activedescendant=\"opt-2\"/>;\n");
        assert_eq!(count_key(&missing, "javascript:S6823"), 1);
    }

    #[test]
    fn s6823_accepts_camel_case_and_lowercase_tab_indices() {
        let camel = jsx_keys(
            "const el = <div role=\"listbox\" aria-activedescendant=\"opt-2\" tabIndex={0}/>;\n",
        );
        assert_eq!(count_key(&camel, "javascript:S6823"), 0);

        let lowercase = jsx_keys(
            "const el = <ul aria-activedescendant=\"opt-2\" tabindex=\"-1\"><li>x</li></ul>;\n",
        );
        assert_eq!(count_key(&lowercase, "javascript:S6823"), 0);
    }

    #[test]
    fn s6823_skips_spread_elements_and_other_attributes() {
        let spread = jsx_keys("const el = <div {...rest} aria-activedescendant=\"opt-2\"/>;\n");
        assert_eq!(count_key(&spread, "javascript:S6823"), 0);

        let unrelated = jsx_keys("const el = <div aria-describedby=\"hint\"/>;\n");
        assert_eq!(count_key(&unrelated, "javascript:S6823"), 0);
    }
}
