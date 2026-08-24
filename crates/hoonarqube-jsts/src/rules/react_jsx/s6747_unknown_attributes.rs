use super::walker::{ReactCollector, jsx_attribute_name, jsx_element_tag, jsx_tag_is_intrinsic};
use crate::REACT_DOM_ATTRIBUTES;
use crate::support::RuleScope;
use oxc_ast::ast::JSXAttributeItem;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl ReactCollector<'_> {
    /// `S6747`: unknown attributes on intrinsic elements.
    pub(crate) fn check_unknown_attributes(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag) {
            return;
        }
        for item in &element.opening_element.attributes {
            let JSXAttributeItem::Attribute(attribute) = item else {
                continue;
            };
            let Some(name) = jsx_attribute_name(attribute) else {
                continue;
            };
            if attribute_is_known(name, &self.rules.jsx_attribute_whitelist) {
                continue;
            }
            let message = format!("'{name}' is not a known DOM or React attribute.");
            self.sink
                .emit_span(RuleScope::Both, "S6747", &message, attribute.span());
        }
    }
}

/// Whether an intrinsic-element attribute is a known DOM/React name
/// (`S6747`): table, configured extras, `data-*`/`aria-*`, and handlers.
pub(crate) fn attribute_is_known(name: &str, whitelist: &[String]) -> bool {
    name.starts_with("data-")
        || name.starts_with("aria-")
        || (name.starts_with("on") && name[2..].starts_with(|ch: char| ch.is_ascii_alphabetic()))
        || REACT_DOM_ATTRIBUTES.contains(&name)
        || whitelist.iter().any(|allowed| allowed == name)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6747_flags_each_unknown_attribute_on_intrinsic_element() {
        let findings = jsx_keys("const el = <div class=\"x\" foo=\"1\"></div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6747"), 2);
    }

    #[test]
    fn s6747_allows_known_dom_attribute() {
        let findings = jsx_keys("const el = <div className=\"foo\"></div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6747"), 0);
    }

    #[test]
    fn s6747_allows_data_aria_and_handler_attributes() {
        let findings =
            jsx_keys("const el = <div data-x=\"1\" aria-hidden=\"true\" onClick={f}></div>;\n");
        assert_eq!(count_key(&findings, "javascript:S6747"), 0);
    }

    #[test]
    fn s6747_ignores_attributes_on_component_elements() {
        let findings = jsx_keys("const el = <Widget arbitrary={1}></Widget>;\n");
        assert_eq!(count_key(&findings, "javascript:S6747"), 0);
    }
}
