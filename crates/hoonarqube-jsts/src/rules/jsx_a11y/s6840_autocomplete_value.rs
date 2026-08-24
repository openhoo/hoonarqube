use super::walker::{
    A11yCollector, attribute_named_static_value, attribute_static_value, jsx_element_tag,
    jsx_find_attribute, jsx_has_spread_attribute,
};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6840`: autocomplete values must fit the element's input type.
    pub(crate) fn check_autocomplete_value(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !matches!(tag, "input" | "select" | "textarea")
            || jsx_has_spread_attribute(&element.opening_element)
        {
            return;
        }
        let Some(autocomplete_attribute) = ["autocomplete", "autoComplete"]
            .iter()
            .find_map(|name| jsx_find_attribute(&element.opening_element, name))
        else {
            return;
        };
        let Some(value) = attribute_static_value(autocomplete_attribute) else {
            return;
        };
        let token = value.trim().to_lowercase();
        let input_type = attribute_named_static_value(&element.opening_element, "type");
        let valid = AUTOCOMPLETE_GENERAL_TOKENS.contains(&token.as_str())
            || AUTOCOMPLETE_TYPE_TOKENS
                .iter()
                .any(|(scoped_type, scoped_token)| {
                    input_type == Some(*scoped_type) && token == *scoped_token
                });
        if !valid {
            let message = format!("\"{value}\" is not a valid 'autocomplete' value here.");
            self.sink.emit_span(
                RuleScope::Both,
                "S6840",
                &message,
                autocomplete_attribute.span(),
            );
        }
    }
}

/// Input types whose autocomplete accepts their matching contact token
/// (`S6840`).
pub(crate) const AUTOCOMPLETE_TYPE_TOKENS: &[(&str, &str)] =
    &[("email", "email"), ("tel", "tel"), ("url", "url")];

/// Autocomplete tokens valid on every autofill-capable element (`S6840`).
pub(crate) const AUTOCOMPLETE_GENERAL_TOKENS: [&str; 14] = [
    "address-line1",
    "address-line2",
    "country",
    "country-name",
    "current-password",
    "given-name",
    "new-password",
    "off",
    "on",
    "one-time-code",
    "organization",
    "postal-code",
    "street-address",
    "username",
];

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6840_flags_scoped_tokens_on_mismatched_input_types() {
        let tel_mismatch = jsx_keys("const el = <input type=\"tel\" autoComplete=\"email\"/>;\n");
        assert_eq!(count_key(&tel_mismatch, "javascript:S6840"), 1);
    }

    #[test]
    fn s6840_accepts_matching_scopes_and_lowercase_spelling() {
        let url_match = jsx_keys("const el = <input type=\"url\" autocomplete=\"url\"/>;\n");
        assert_eq!(count_key(&url_match, "javascript:S6840"), 0);

        let general_token = jsx_keys("const el = <select autoComplete=\"country-name\"/>;\n");
        assert_eq!(count_key(&general_token, "javascript:S6840"), 0);
    }

    #[test]
    fn s6840_skips_spreads_dynamic_values_and_other_tags() {
        let spread = jsx_keys("const el = <input {...rest} autoComplete=\"banana\"/>;\n");
        assert_eq!(count_key(&spread, "javascript:S6840"), 0);

        let dynamic = jsx_keys("let v = 'email';\nconst el = <input autoComplete={v}/>;\n");
        assert_eq!(count_key(&dynamic, "javascript:S6840"), 0);

        let other_tag = jsx_keys("const el = <div autoComplete=\"banana\"/>;\n");
        assert_eq!(count_key(&other_tag, "javascript:S6840"), 0);
    }
}
