use super::walker::{
    A11yCollector, attribute_static_value, jsx_element_tag, jsx_find_attribute,
    jsx_has_spread_attribute,
};
use crate::language_tag_is_valid;
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S5254`: the root `<html>` element needs a valid language tag.
    pub(crate) fn check_html_lang(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("html")
            || jsx_has_spread_attribute(&element.opening_element)
        {
            return;
        }
        let lang_valid = jsx_find_attribute(&element.opening_element, "lang")
            .and_then(attribute_static_value)
            .is_some_and(language_tag_is_valid);
        if !lang_valid {
            self.sink.emit_span(
                RuleScope::Both,
                "S5254",
                "Give the <html> element a valid 'lang' attribute.",
                element.opening_element.span(),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s5254_flags_html_elements_with_missing_or_invalid_lang() {
        let missing = jsx_keys("const el = <html><body/></html>;\n");
        assert_eq!(count_key(&missing, "javascript:S5254"), 1);

        let invalid = jsx_keys("const el = <html lang=\"english!\"><body/></html>;\n");
        assert_eq!(count_key(&invalid, "javascript:S5254"), 1);
    }

    #[test]
    fn s5254_accepts_valid_language_tags() {
        let region = jsx_keys("const el = <html lang=\"de-DE\"><body/></html>;\n");
        assert_eq!(count_key(&region, "javascript:S5254"), 0);

        let base = jsx_keys("const el = <html lang=\"fr\"><body/></html>;\n");
        assert_eq!(count_key(&base, "javascript:S5254"), 0);
    }

    #[test]
    fn s5254_skips_spread_html_and_other_tags() {
        let spread = jsx_keys("const el = <html {...props}><body/></html>;\n");
        assert_eq!(count_key(&spread, "javascript:S5254"), 0);

        let other_tag = jsx_keys("const el = <div lang=\"e\"/>;\n");
        assert_eq!(count_key(&other_tag, "javascript:S5254"), 0);
    }
}
