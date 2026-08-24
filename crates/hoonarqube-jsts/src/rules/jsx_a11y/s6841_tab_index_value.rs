use super::walker::{A11yCollector, attribute_integer_value, jsx_find_attribute};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6841`: tab indices are restricted to 0 and -1.
    pub(crate) fn check_tab_index_value(&mut self, element: &JSXElement<'_>) {
        let Some(index_attribute) = ["tabIndex", "tabindex"]
            .iter()
            .find_map(|name| jsx_find_attribute(&element.opening_element, name))
        else {
            return;
        };
        match attribute_integer_value(index_attribute) {
            Some(0 | -1) | None => {}
            Some(_) => {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S6841",
                    "Use only 0 or -1 for 'tabIndex'.",
                    index_attribute.span(),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6841_flags_positive_numeric_and_string_tab_indices() {
        let numeric = jsx_keys("const el = <div tabIndex={5}/>;\n");
        assert_eq!(count_key(&numeric, "javascript:S6841"), 1);

        let string_value = jsx_keys("const el = <div tabIndex=\"5\"/>;\n");
        assert_eq!(count_key(&string_value, "javascript:S6841"), 1);
    }

    #[test]
    fn s6841_accepts_zero_minus_one_and_dynamic_values() {
        let zero = jsx_keys("const el = <div tabIndex={0}/>;\n");
        assert_eq!(count_key(&zero, "javascript:S6841"), 0);

        let minus_one = jsx_keys("const el = <div tabIndex={-1}/>;\n");
        assert_eq!(count_key(&minus_one, "javascript:S6841"), 0);

        let dynamic = jsx_keys("let t = 2;\nconst el = <div tabIndex={t}/>;\n");
        assert_eq!(count_key(&dynamic, "javascript:S6841"), 0);
    }

    #[test]
    fn s6841_checks_lowercase_spelling_too() {
        let lowercase = jsx_keys("const el = <div tabindex=\"3\"/>;\n");
        assert_eq!(count_key(&lowercase, "javascript:S6841"), 1);
    }
}
