use super::walker::{
    A11yCollector, attribute_integer_value, explicit_role, is_interactive_element,
    is_interactive_role, jsx_element_tag, jsx_find_attribute, jsx_has_spread_attribute,
    jsx_tag_is_intrinsic,
};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6845`: positive tab indices belong on interactive elements.
    pub(crate) fn check_noninteractive_tab_index(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag)
            || jsx_has_spread_attribute(&element.opening_element)
            || is_interactive_element(tag, &element.opening_element)
            || jsx_find_attribute(&element.opening_element, "aria-activedescendant").is_some()
        {
            return;
        }
        let Some(index_attribute) = ["tabIndex", "tabindex"]
            .iter()
            .find_map(|name| jsx_find_attribute(&element.opening_element, name))
        else {
            return;
        };
        let focusable_by_role =
            explicit_role(&element.opening_element).is_some_and(is_interactive_role);
        if !focusable_by_role
            && attribute_integer_value(index_attribute).is_some_and(|value| value >= 0)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6845",
                "Remove this positive 'tabIndex'; make the element properly interactive instead.",
                index_attribute.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6845_flags_positive_indices_on_static_elements() {
        let paragraph = jsx_keys("const el = <p tabIndex={0}>text</p>;\n");
        assert_eq!(count_key(&paragraph, "javascript:S6845"), 1);

        let lowercase = jsx_keys("const el = <span tabindex=\"1\"/>;\n");
        assert_eq!(count_key(&lowercase, "javascript:S6845"), 1);
    }

    #[test]
    fn s6845_accepts_programmatic_and_role_focusable_elements() {
        let negative = jsx_keys("const el = <p tabIndex={-1}>text</p>;\n");
        assert_eq!(count_key(&negative, "javascript:S6845"), 0);

        let interactive_role = jsx_keys("const el = <span role=\"option\" tabIndex={0}/>;\n");
        assert_eq!(count_key(&interactive_role, "javascript:S6845"), 0);
    }

    #[test]
    fn s6845_skips_interactive_tags_spreads_and_activedescendant() {
        let input_field = jsx_keys("const el = <input type=\"text\" tabIndex={0}/>;\n");
        assert_eq!(count_key(&input_field, "javascript:S6845"), 0);

        let spread = jsx_keys("const el = <div {...rest} tabIndex={0}/>;\n");
        assert_eq!(count_key(&spread, "javascript:S6845"), 0);

        let activedescendant =
            jsx_keys("const el = <div aria-activedescendant=\"o1\" tabIndex={0}/>;\n");
        assert_eq!(count_key(&activedescendant, "javascript:S6845"), 0);
    }
}
