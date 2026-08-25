use super::walker::{
    A11yCollector, explicit_role, is_interactive_element, is_interactive_role, jsx_attribute_name,
    jsx_element_tag, jsx_has_spread_attribute, jsx_tag_is_intrinsic,
};
use crate::support::RuleScope;
use oxc_ast::ast::JSXAttributeItem;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6847`: interaction handlers belong on interactive elements.
    pub(crate) fn check_noninteractive_handlers(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag)
            || jsx_has_spread_attribute(&element.opening_element)
            || is_interactive_element(tag, &element.opening_element)
            || explicit_role(&element.opening_element).is_some_and(is_interactive_role)
        {
            return;
        }
        for item in &element.opening_element.attributes {
            let JSXAttributeItem::Attribute(attribute) = item else {
                continue;
            };
            let Some(name) = jsx_attribute_name(attribute) else {
                continue;
            };
            if INTERACTION_HANDLERS.contains(&name) {
                let message = format!("Move this '{name}' handler to an interactive element.");
                self.sink
                    .emit_span(RuleScope::Both, "S6847", &message, attribute.span());
            }
        }
    }
}

/// Interaction handler props the matrix rules consider (`S6847`).
const INTERACTION_HANDLERS: [&str; 8] = [
    "onChange",
    "onClick",
    "onDoubleClick",
    "onKeyDown",
    "onKeyPress",
    "onKeyUp",
    "onMouseDown",
    "onMouseUp",
];

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6847_flags_each_interaction_handler_on_static_paragraphs() {
        let three_handlers =
            jsx_keys("const el = <p onDoubleClick={f} onKeyPress={g} onKeyUp={h}/>;\n");
        assert_eq!(count_key(&three_handlers, "javascript:S6847"), 3);
    }

    #[test]
    fn s6847_accepts_handlers_on_interactive_inputs() {
        let input_field = jsx_keys(
            "const el = <input type=\"text\" onChange={f} onKeyDown={k} onMouseUp={u}/>;\n",
        );
        assert_eq!(count_key(&input_field, "javascript:S6847"), 0);
    }

    #[test]
    fn s6847_skips_spread_elements_and_interactive_roles() {
        let spread = jsx_keys("const el = <p {...rest} onClick={f}/>;\n");
        assert_eq!(count_key(&spread, "javascript:S6847"), 0);

        let interactive_role = jsx_keys("const el = <p role=\"option\" onKeyDown={k}/>; \n");
        assert_eq!(count_key(&interactive_role, "javascript:S6847"), 0);
    }
}
