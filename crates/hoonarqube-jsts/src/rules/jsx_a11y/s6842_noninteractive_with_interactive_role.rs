use super::walker::{
    A11yCollector, explicit_role, is_interactive_element, is_interactive_role, jsx_element_tag,
    jsx_find_attribute, jsx_has_spread_attribute, jsx_tag_is_intrinsic,
};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6842`: interactive roles belong on natively interactive elements.
    pub(crate) fn check_noninteractive_with_interactive_role(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag)
            || jsx_has_spread_attribute(&element.opening_element)
            || is_interactive_element(tag, &element.opening_element)
        {
            return;
        }
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        if is_interactive_role(role) {
            let message = format!(
                "Replace this <{tag}> with an interactive element or remove the '{role}' role."
            );
            let role_attribute = jsx_find_attribute(&element.opening_element, "role");
            self.sink.emit_span(
                RuleScope::Both,
                "S6842",
                &message,
                role_attribute.map_or(element.span(), GetSpan::span),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6842_flags_interactive_roles_on_static_anchors() {
        let anchor_link = jsx_keys("const el = <a role=\"link\" tabIndex={0}>docs</a>;\n");
        assert_eq!(count_key(&anchor_link, "javascript:S6842"), 1);
    }

    #[test]
    fn s6842_accepts_native_controls_and_structural_roles() {
        let native_button = jsx_keys("const el = <button>OK</button>;\n");
        assert_eq!(count_key(&native_button, "javascript:S6842"), 0);

        let structural = jsx_keys("const el = <div role=\"note\">x</div>;\n");
        assert_eq!(count_key(&structural, "javascript:S6842"), 0);

        let linked_anchor = jsx_keys("const el = <a href=\"/docs\" role=\"link\">docs</a>;\n");
        assert_eq!(count_key(&linked_anchor, "javascript:S6842"), 0);
    }

    #[test]
    fn s6842_skips_spread_elements_and_missing_roles() {
        let spread = jsx_keys("const el = <span {...rest} role=\"link\">x</span>;\n");
        assert_eq!(count_key(&spread, "javascript:S6842"), 0);

        let no_role = jsx_keys("const el = <span>x</span>;\n");
        assert_eq!(count_key(&no_role, "javascript:S6842"), 0);
    }
}
