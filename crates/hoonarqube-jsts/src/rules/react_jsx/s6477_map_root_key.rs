use super::walker::ReactCollector;
use crate::rules::shared::jsx_find_attribute;
use crate::support::RuleScope;
use oxc_ast::ast::JSXAttributeItem;
use oxc_ast::ast::JSXElement;
use oxc_ast::ast::JSXOpeningElement;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6477`: root elements returned from `.map()` callbacks need keys.
    /// CE-parity: callbacks without an index parameter are flagged too (the
    /// documented noncompliant example is `(post) => <li>`; the captured
    /// engine fires on oracle-js `s6477_good.jsx`).
    pub(crate) fn check_map_root_key(&mut self, element: &JSXElement<'_>) {
        let Some(frame) = self.map_frames.last_mut() else {
            return;
        };
        if frame.root_checked {
            return;
        }
        frame.root_checked = true;
        if jsx_has_spread_attribute(&element.opening_element)
            || jsx_find_attribute(&element.opening_element, "key").is_some()
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6477",
            "Missing \"key\" prop for element in iterator",
            element.span(),
        );
    }
}

/// Whether the opening tag carries a spread attribute (unknown props).
fn jsx_has_spread_attribute(opening: &JSXOpeningElement<'_>) -> bool {
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
    fn s6477_flags_callback_without_index_parameter() {
        // CE-parity flip: single-parameter callbacks are noncompliant too
        // (oracle-js s6477_good.jsx); the old index-param requirement made us
        // miss what the captured engine reports.
        let findings = jsx_keys("items.map((item) => <li></li>);\n");
        assert_eq!(count_key(&findings, "javascript:S6477"), 1);
    }

    #[test]
    fn s6477_allows_spread_attribute_root() {
        let findings = jsx_keys("items.map((item) => <li {...item.props}></li>);\n");
        assert_eq!(count_key(&findings, "javascript:S6477"), 0);
    }
}
