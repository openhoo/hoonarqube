use super::walker::{
    A11yCollector, explicit_role, is_interactive_element, jsx_element_tag, jsx_find_attribute,
    jsx_has_spread_attribute, jsx_tag_is_intrinsic,
};
use crate::NON_INTERACTIVE_ROLES;
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6843`: interactive elements must not take structural roles.
    pub(crate) fn check_interactive_with_noninteractive_role(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag)
            || jsx_has_spread_attribute(&element.opening_element)
            || !is_interactive_element(tag, &element.opening_element)
        {
            return;
        }
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        if is_non_interactive_role(role) {
            let message = format!("Interactive <{tag}> elements cannot take the '{role}' role.");
            let role_attribute = jsx_find_attribute(&element.opening_element, "role");
            self.sink.emit_span(
                RuleScope::Both,
                "S6843",
                &message,
                role_attribute.map_or(element.span(), GetSpan::span),
            );
        }
    }
}

/// Whether an explicit role is a purely structural or document role.
fn is_non_interactive_role(role: &str) -> bool {
    NON_INTERACTIVE_ROLES.contains(&role)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6843_flags_structural_roles_on_interactive_selects() {
        let select_article = jsx_keys("const el = <select role=\"article\"/>;\n");
        assert_eq!(count_key(&select_article, "javascript:S6843"), 1);

        let textarea_banner = jsx_keys("const el = <textarea role=\"banner\"/>;\n");
        assert_eq!(count_key(&textarea_banner, "javascript:S6843"), 1);
    }

    #[test]
    fn s6843_accepts_matching_or_omitted_roles() {
        let matching = jsx_keys("const el = <button role=\"checkbox\"/>;\n");
        assert_eq!(count_key(&matching, "javascript:S6843"), 0);

        let no_role = jsx_keys("const el = <button/>;\n");
        assert_eq!(count_key(&no_role, "javascript:S6843"), 0);

        let static_element = jsx_keys("const el = <div role=\"banner\">x</div>;\n");
        assert_eq!(count_key(&static_element, "javascript:S6843"), 0);
    }

    #[test]
    fn s6843_skips_spread_elements_and_hrefless_anchors() {
        let spread = jsx_keys("const el = <button {...rest} role=\"list\"/>;\n");
        assert_eq!(count_key(&spread, "javascript:S6843"), 0);

        let hrefless = jsx_keys("const el = <a role=\"list\">x</a>;\n");
        assert_eq!(count_key(&hrefless, "javascript:S6843"), 0);
    }
}
