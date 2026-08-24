use super::walker::{
    A11yCollector, explicit_role, is_interactive_element, is_interactive_role, jsx_element_tag,
    jsx_find_attribute, jsx_has_spread_attribute, jsx_tag_is_intrinsic,
};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6852`: elements with an interactive role must be focusable.
    pub(crate) fn check_interactive_role_focusable(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag) || jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        if !is_interactive_role(role)
            || is_interactive_element(tag, &element.opening_element)
            || ["tabIndex", "tabindex"]
                .iter()
                .any(|name| jsx_find_attribute(&element.opening_element, name).is_some())
        {
            return;
        }
        let message =
            format!("Elements with the '{role}' role must be focusable; add a 'tabIndex'.");
        let role_attribute = jsx_find_attribute(&element.opening_element, "role");
        self.sink.emit_span(
            RuleScope::Both,
            "S6852",
            &message,
            role_attribute.map_or(element.span(), GetSpan::span),
        );
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6852_flags_interactive_roles_without_tab_index() {
        let span = jsx_keys("const el = <span role=\"checkbox\"/>;\n");
        assert_eq!(count_key(&span, "javascript:S6852"), 1);

        let list_item = jsx_keys("const el = <li role=\"option\">One</li>;\n");
        assert_eq!(count_key(&list_item, "javascript:S6852"), 1);
    }

    #[test]
    fn s6852_accepts_tabbable_and_natively_focusable_elements() {
        let tabbable = jsx_keys("const el = <span role=\"checkbox\" tabIndex={0}/>;\n");
        assert_eq!(count_key(&tabbable, "javascript:S6852"), 0);

        let lowercase = jsx_keys("const el = <div role=\"radio\" tabindex=\"0\"/>;\n");
        assert_eq!(count_key(&lowercase, "javascript:S6852"), 0);

        let native_button = jsx_keys("const el = <button role=\"button\"/>;\n");
        assert_eq!(count_key(&native_button, "javascript:S6852"), 0);
    }

    #[test]
    fn s6852_skips_spread_elements_and_custom_components() {
        let spread = jsx_keys("const el = <div {...rest} role=\"button\"/>;\n");
        assert_eq!(count_key(&spread, "javascript:S6852"), 0);

        let custom = jsx_keys("const el = <FancyButton role=\"button\"/>;\n");
        assert_eq!(count_key(&custom, "javascript:S6852"), 0);
    }
}
