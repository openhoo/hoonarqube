use super::walker::{ReactCollector, jsx_find_attribute};
use crate::support::RuleScope;
use oxc_ast::ast::JSXAttributeItem;
use oxc_ast::ast::JSXElement;
use oxc_ast::ast::JSXOpeningElement;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6477`: root elements returned from `.map()` callbacks need keys.
    pub(crate) fn check_map_root_key(&mut self, element: &JSXElement<'_>) {
        let needs_key = match self.map_frames.last_mut() {
            Some(frame) if !frame.root_checked => {
                frame.root_checked = true;
                frame.index_param.is_some()
            }
            _ => return,
        };
        if !needs_key
            || jsx_has_spread_attribute(&element.opening_element)
            || jsx_find_attribute(&element.opening_element, "key").is_some()
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6477",
            "Add a 'key' prop to this element returned from '.map()'.",
            element.opening_element.span(),
        );
    }
}

/// Whether the opening tag carries a spread attribute (unknown props).
pub(crate) fn jsx_has_spread_attribute(opening: &JSXOpeningElement<'_>) -> bool {
    opening
        .attributes
        .iter()
        .any(|item| matches!(item, JSXAttributeItem::SpreadAttribute(_)))
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6477_flags_keyless_map_root_element() {
        let findings = jsx_keys("items.map((item, index) => <li></li>);\n");
        assert_eq!(count_key(&findings, "javascript:S6477"), 1);
    }

    #[test]
    fn s6477_allows_root_element_with_key() {
        let findings = jsx_keys("items.map((item, index) => <li key={item.id}></li>);\n");
        assert_eq!(count_key(&findings, "javascript:S6477"), 0);
    }

    #[test]
    fn s6477_ignores_callback_without_index_parameter() {
        let findings = jsx_keys("items.map((item) => <li></li>);\n");
        assert_eq!(count_key(&findings, "javascript:S6477"), 0);
    }
}
