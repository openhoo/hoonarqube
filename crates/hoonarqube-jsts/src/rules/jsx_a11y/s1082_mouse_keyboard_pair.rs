use super::walker::{A11yCollector, jsx_find_attribute, jsx_has_spread_attribute};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S1082`: mouse-over/out handlers need focus/blur counterparts.
    pub(crate) fn check_mouse_keyboard_pair(&mut self, element: &JSXElement<'_>) {
        if jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        for (mouse, keyboard) in [("onMouseOver", "onFocus"), ("onMouseOut", "onBlur")] {
            let Some(mouse_attribute) = jsx_find_attribute(&element.opening_element, mouse) else {
                continue;
            };
            if jsx_find_attribute(&element.opening_element, keyboard).is_none() {
                let message =
                    format!("Add the '{keyboard}' handler to pair with this '{mouse}' handler.");
                self.sink
                    .emit_span(RuleScope::Both, "S1082", &message, mouse_attribute.span());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s1082_flags_mouse_out_handler_without_blur_counterpart() {
        let alone = jsx_keys("const el = <div onMouseOut={leave}/>;\n");
        assert_eq!(count_key(&alone, "javascript:S1082"), 1);
    }

    #[test]
    fn s1082_reports_only_the_unpaired_mouse_handler() {
        let half_paired =
            jsx_keys("const el = <div onMouseOver={show} onMouseOut={leave} onFocus={focus}/>;\n");
        assert_eq!(count_key(&half_paired, "javascript:S1082"), 1);
    }

    #[test]
    fn s1082_accepts_fully_paired_and_spread_elements() {
        let paired = jsx_keys(
            "const el = <div onMouseOver={show} onFocus={focus} onMouseOut={leave} onBlur={hide}/>;\n",
        );
        assert_eq!(count_key(&paired, "javascript:S1082"), 0);

        let spread = jsx_keys("const el = <div {...handlers} onMouseOver={show}/>;\n");
        assert_eq!(count_key(&spread, "javascript:S1082"), 0);
    }
}
