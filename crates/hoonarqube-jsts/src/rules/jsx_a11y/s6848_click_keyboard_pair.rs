use super::walker::{
    A11yCollector, explicit_role, is_interactive_element, is_interactive_role, jsx_element_tag,
    jsx_find_attribute, jsx_has_spread_attribute, jsx_tag_is_intrinsic,
};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6848`: click handlers need keyboard counterparts on
    /// non-interactive elements.
    pub(crate) fn check_click_keyboard_pair(&mut self, element: &JSXElement<'_>) {
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
        let Some(click_attribute) = jsx_find_attribute(&element.opening_element, "onClick") else {
            return;
        };
        if KEYBOARD_HANDLERS
            .iter()
            .any(|name| jsx_find_attribute(&element.opening_element, name).is_some())
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6848",
            "Add a keyboard handler ('onKeyDown', 'onKeyPress', or 'onKeyUp') to pair with this 'onClick'.",
            click_attribute.span(),
        );
    }
}

/// Keyboard handlers that pair with `onClick` for `S6848`.
const KEYBOARD_HANDLERS: [&str; 3] = ["onKeyDown", "onKeyPress", "onKeyUp"];

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6848_flags_click_without_keyboard_on_list_items() {
        let click_only = jsx_keys("const el = <li onClick={select}>One</li>;\n");
        assert_eq!(count_key(&click_only, "javascript:S6848"), 1);
    }

    #[test]
    fn s6848_accepts_alternate_keyboard_counterparts() {
        let key_press = jsx_keys("const el = <li onClick={select} onKeyPress={k}>One</li>;\n");
        assert_eq!(count_key(&key_press, "javascript:S6848"), 0);

        let key_up = jsx_keys("const el = <li onClick={select} onKeyUp={k}>One</li>;\n");
        assert_eq!(count_key(&key_up, "javascript:S6848"), 0);
    }

    #[test]
    fn s6848_skips_interactive_elements_and_spreads() {
        let input_field = jsx_keys("const el = <input type=\"text\" onClick={f}/>;\n");
        assert_eq!(count_key(&input_field, "javascript:S6848"), 0);

        let interactive_role =
            jsx_keys("const el = <div role=\"menuitem\" onClick={f}>Open</div>;\n");
        assert_eq!(count_key(&interactive_role, "javascript:S6848"), 0);

        let spread = jsx_keys("const el = <div {...rest} onClick={f}/>;\n");
        assert_eq!(count_key(&spread, "javascript:S6848"), 0);
    }
}
