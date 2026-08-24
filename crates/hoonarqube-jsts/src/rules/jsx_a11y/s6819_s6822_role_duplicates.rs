use super::walker::{
    A11yCollector, attribute_static_value, explicit_role, jsx_element_tag, jsx_find_attribute,
    jsx_tag_is_intrinsic,
};
use crate::IMPLICIT_ROLES;
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_ast::ast::JSXOpeningElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6822` and `S6819`: explicit roles duplicating the implicit ones.
    pub(crate) fn check_role_duplicates(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag) {
            return;
        }
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        if implicit_role(tag, &element.opening_element) != Some(role) {
            return;
        }
        let Some(role_attribute) = jsx_find_attribute(&element.opening_element, "role") else {
            return;
        };
        self.sink.emit_span(
            RuleScope::Both,
            "S6822",
            "This 'role' duplicates the element's implicit role; remove it.",
            role_attribute.span(),
        );
        self.sink.emit_span(
            RuleScope::Both,
            "S6819",
            "Remove this explicit 'role'; the element already has these semantics implicitly.",
            role_attribute.span(),
        );
    }
}

/// Implicit ARIA role of an intrinsic tag, refined by `a[href]` and
/// `input[type]`.
pub(crate) fn implicit_role(tag: &str, opening: &JSXOpeningElement) -> Option<&'static str> {
    match tag {
        "a" | "area" => jsx_find_attribute(opening, "href").map(|_| "link"),
        "input" => {
            let input_type = jsx_find_attribute(opening, "type").and_then(attribute_static_value);
            Some(match input_type {
                Some("checkbox") => "checkbox",
                Some("radio") => "radio",
                Some("button" | "image") => "button",
                Some("number") => "spinbutton",
                Some("range") => "slider",
                Some("search") => "searchbox",
                _ => "textbox",
            })
        }
        _ => IMPLICIT_ROLES
            .iter()
            .find(|(name, _)| *name == tag)
            .map(|(_, role)| *role),
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6819_s6822_flag_duplicated_checkbox_roles() {
        let checkbox = jsx_keys("const el = <input type=\"checkbox\" role=\"checkbox\"/>;\n");
        assert_eq!(count_key(&checkbox, "javascript:S6819"), 1);
        assert_eq!(count_key(&checkbox, "javascript:S6822"), 1);
    }

    #[test]
    fn s6819_s6822_accept_changed_or_omitted_roles() {
        let changed = jsx_keys("const el = <input type=\"text\" role=\"combobox\"/>;\n");
        assert_eq!(count_key(&changed, "javascript:S6819"), 0);
        assert_eq!(count_key(&changed, "javascript:S6822"), 0);

        let no_role = jsx_keys("const el = <input type=\"radio\"/>;\n");
        assert_eq!(count_key(&no_role, "javascript:S6819"), 0);
        assert_eq!(count_key(&no_role, "javascript:S6822"), 0);
    }

    #[test]
    fn s6819_s6822_only_duplicate_when_href_makes_the_link() {
        let linked = jsx_keys("const el = <a href=\"/docs\" role=\"link\">docs</a>;\n");
        assert_eq!(count_key(&linked, "javascript:S6819"), 1);
        assert_eq!(count_key(&linked, "javascript:S6822"), 1);

        let hrefless = jsx_keys("const el = <a role=\"link\">docs</a>;\n");
        assert_eq!(count_key(&hrefless, "javascript:S6819"), 0);
        assert_eq!(count_key(&hrefless, "javascript:S6822"), 0);
    }
}
