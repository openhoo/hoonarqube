use super::walker::{A11yCollector, jsx_attribute_name};
use crate::support::RuleScope;
use oxc_ast::ast::JSXAttributeItem;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6846`: access keys conflict with assistive shortcuts.
    pub(crate) fn check_accesskey(&mut self, element: &JSXElement<'_>) {
        for item in &element.opening_element.attributes {
            let JSXAttributeItem::Attribute(attribute) = item else {
                continue;
            };
            if jsx_attribute_name(attribute) == Some("accesskey") {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6846",
                    "Remove this 'accesskey'; it conflicts with assistive technology shortcuts.",
                    attribute.span(),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6846_flags_accesskey_attributes() {
        let flagged = jsx_keys("const el = <div accesskey=\"s\"/>;\n");
        assert_eq!(count_key(&flagged, "javascript:S6846"), 1);
    }

    #[test]
    fn s6846_counts_every_flagged_element_in_a_tree() {
        let nested = jsx_keys(
            "const el = <div accesskey=\"s\"><span accesskey=\"p\">Profile</span></div>;\n",
        );
        assert_eq!(count_key(&nested, "javascript:S6846"), 2);
    }

    #[test]
    fn s6846_ignores_elements_without_accesskeys() {
        let clean = jsx_keys("const el = <div title=\"s\">Profile</div>;\n");
        assert_eq!(count_key(&clean, "javascript:S6846"), 0);
    }
}
