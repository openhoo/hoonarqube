use super::collectors::{REACT_DOM_ATTRIBUTES, TAG_SCOPED_ATTRIBUTES};
use super::walker::ReactCollector;
use crate::rules::shared::{jsx_attribute_name, jsx_element_tag, jsx_tag_is_intrinsic};
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
            // Configured extras win over every other check, like the
            // reference `ignore` option.
            if self
                .rules
                .jsx_attribute_whitelist
                .iter()
                .any(|allowed| allowed == name)
            {
                continue;
            }
            // Tag-scoped names are known only on their allowed tags; on any
            // other tag the reference reports `invalidPropOnTag`.
            if let Some(allowed_tags) = tag_scoped_allowed_tags(name) {
                if allowed_tags.contains(&tag) {
                    continue;
                }
                let message = format!(
                    "Invalid property '{name}' found on tag '{tag}', but it is only allowed on: {}",
                    allowed_tags.join(", ")
                );
                self.sink
                    .emit_span(RuleScope::Both, "S6747", &message, attribute.span());
                continue;
            }
            if attribute_is_known(name) {
                continue;
            }
            let message = format!("'{name}' is not a known DOM or React attribute.");
            self.sink
                .emit_span(RuleScope::Both, "S6747", &message, attribute.span());
        }
    }
}

/// Whether an intrinsic-element attribute is a known DOM/React name
/// (`S6747`): table plus `data-*`/`aria-*` prefixes and `on*` handlers.
/// Tag-scoped names are handled separately by `tag_scoped_allowed_tags`.
fn attribute_is_known(name: &str) -> bool {
    name.starts_with("data-")
        || name.starts_with("aria-")
        || (name.starts_with("on") && name[2..].starts_with(|ch: char| ch.is_ascii_alphabetic()))
        || REACT_DOM_ATTRIBUTES.contains(&name)
}

/// Allowed intrinsic tags for a tag-scoped attribute name (`S6747`), if the
/// name is restricted to specific elements (for example `as` on `<link>`).
fn tag_scoped_allowed_tags(name: &str) -> Option<&'static [&'static str]> {
    TAG_SCOPED_ATTRIBUTES
        .iter()
        .find_map(|(attr, tags)| (*attr == name).then_some(*tags))
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

    #[test]
    fn s6747_allows_as_attribute_on_link() {
        let preload =
            jsx_keys("const el = <link rel=\"preload\" href=\"/font.woff2\" as=\"font\" />;\n");
        assert_eq!(count_key(&preload, "javascript:S6747"), 0);
    }

    #[test]
    fn s6747_allows_other_tag_scoped_attributes_on_their_tags() {
        let meta = jsx_keys("const el = <meta charset=\"utf-8\" />;\n");
        assert_eq!(count_key(&meta, "javascript:S6747"), 0);

        let svg = jsx_keys("const el = <svg viewBox=\"0 0 1 1\"></svg>;\n");
        assert_eq!(count_key(&svg, "javascript:S6747"), 0);
    }

    #[test]
    fn s6747_flags_tag_scoped_attributes_on_other_tags() {
        let div_as = jsx_keys("const el = <div as=\"font\"></div>;\n");
        assert_eq!(count_key(&div_as, "javascript:S6747"), 1);

        let div_checked = jsx_keys("const el = <div checked></div>;\n");
        assert_eq!(count_key(&div_checked, "javascript:S6747"), 1);
    }
}
