use super::walker::{A11yCollector, attribute_static_value, jsx_attribute_name};
use crate::support::RuleScope;
use oxc_ast::ast::JSXAttributeItem;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6793`: literal ARIA attribute values validated against tables.
    pub(crate) fn check_aria_values(&mut self, element: &JSXElement<'_>) {
        for item in &element.opening_element.attributes {
            let JSXAttributeItem::Attribute(attribute) = item else {
                continue;
            };
            let Some(name) = jsx_attribute_name(attribute) else {
                continue;
            };
            let Some(value) = attribute_static_value(attribute) else {
                continue;
            };
            let invalid = if BOOLEAN_ARIA_PROPERTIES.contains(&name) {
                !matches!(value, "true" | "false")
            } else if let Some((_, tokens)) = TOKEN_ARIA_PROPERTIES
                .iter()
                .find(|(property, _)| *property == name)
            {
                !matches!(value, "true" | "false") && !tokens.contains(&value)
            } else if NUMERIC_ARIA_PROPERTIES.contains(&name) {
                value.parse::<u32>().is_err()
            } else {
                continue;
            };
            if invalid {
                let message = format!("'{value}' is not a valid value for '{name}'.");
                self.sink
                    .emit_span(RuleScope::Both, "S6793", &message, attribute.span());
            }
        }
    }
}

/// Numeric ARIA attributes validated as non-negative integers (`S6793`).
const NUMERIC_ARIA_PROPERTIES: [&str; 3] = ["aria-level", "aria-posinset", "aria-setsize"];

/// Token-set ARIA attributes and their accepted literal values (`S6793`);
/// `"true"`/`"false"` are valid for every entry.
const TOKEN_ARIA_PROPERTIES: &[(&str, &[&str])] = &[
    (
        "aria-current",
        &["page", "step", "location", "date", "time"],
    ),
    (
        "aria-haspopup",
        &["menu", "listbox", "tree", "grid", "dialog"],
    ),
    ("aria-invalid", &["grammar", "spelling"]),
    ("aria-live", &["off", "assertive", "polite"]),
    ("aria-orientation", &["horizontal", "vertical"]),
    ("aria-sort", &["ascending", "descending", "other"]),
];

/// Strictly boolean-valued ARIA attributes (`S6793`).
const BOOLEAN_ARIA_PROPERTIES: [&str; 13] = [
    "aria-atomic",
    "aria-busy",
    "aria-checked",
    "aria-disabled",
    "aria-expanded",
    "aria-grabbed",
    "aria-hidden",
    "aria-modal",
    "aria-multiline",
    "aria-multiselectable",
    "aria-pressed",
    "aria-readonly",
    "aria-selected",
];

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6793_flags_bad_tokens_and_negative_numerics() {
        let bad_popup = jsx_keys("const el = <div aria-haspopup=\"list\"/>;\n");
        assert_eq!(count_key(&bad_popup, "javascript:S6793"), 1);

        let negative = jsx_keys("const el = <div aria-posinset=\"-2\"/>;\n");
        assert_eq!(count_key(&negative, "javascript:S6793"), 1);
    }

    #[test]
    fn s6793_rejects_mixed_on_strictly_boolean_properties() {
        let mixed = jsx_keys("const el = <div role=\"checkbox\" aria-checked=\"mixed\"/>;\n");
        assert_eq!(count_key(&mixed, "javascript:S6793"), 1);

        let boolean_ok = jsx_keys("const el = <div role=\"checkbox\" aria-checked=\"true\"/>;\n");
        assert_eq!(count_key(&boolean_ok, "javascript:S6793"), 0);
    }

    #[test]
    fn s6793_accepts_valid_tokens_and_skips_dynamic_values() {
        let current = jsx_keys("const el = <a href=\"/docs\" aria-current=\"date\">docs</a>;\n");
        assert_eq!(count_key(&current, "javascript:S6793"), 0);

        let sort = jsx_keys("const el = <table aria-sort=\"descending\"/>;\n");
        assert_eq!(count_key(&sort, "javascript:S6793"), 0);

        let dynamic = jsx_keys("let v = 'list';\nconst el = <div aria-haspopup={v}/>;\n");
        assert_eq!(count_key(&dynamic, "javascript:S6793"), 0);
    }
}
