use super::walker::{A11yCollector, explicit_role, jsx_attribute_name};
use crate::support::RuleScope;
use oxc_ast::ast::JSXAttributeItem;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6811`: known ARIA properties must be supported by the explicit
    /// role (globals are always allowed).
    pub(crate) fn check_supported_properties(&mut self, element: &JSXElement<'_>) {
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        let Some(supported) = ROLE_SUPPORTED_PROPERTIES
            .iter()
            .find(|(name, _)| *name == role)
            .map(|(_, properties)| *properties)
        else {
            return;
        };
        for item in &element.opening_element.attributes {
            let JSXAttributeItem::Attribute(attribute) = item else {
                continue;
            };
            let Some(name) = jsx_attribute_name(attribute) else {
                continue;
            };
            if !KNOWN_ARIA_PROPERTIES.contains(&name)
                || GLOBAL_ARIA_PROPERTIES.contains(&name)
                || supported.contains(&name)
            {
                continue;
            }
            let message = format!("'{name}' is not supported by role '{role}'.");
            self.sink
                .emit_span(RuleScope::Both, "S6811", &message, attribute.span());
        }
    }
}

/// Global ARIA properties valid on every role (`S6811` exemptions).
const GLOBAL_ARIA_PROPERTIES: [&str; 18] = [
    "aria-atomic",
    "aria-busy",
    "aria-controls",
    "aria-current",
    "aria-describedby",
    "aria-disabled",
    "aria-dropeffect",
    "aria-errormessage",
    "aria-flowto",
    "aria-grabbed",
    "aria-haspopup",
    "aria-hidden",
    "aria-invalid",
    "aria-keyshortcuts",
    "aria-label",
    "aria-labelledby",
    "aria-live",
    "aria-owns",
];

/// Every ARIA property this subset knows (`S6811` only judges names it
/// recognizes; unknown names stay silent).
const KNOWN_ARIA_PROPERTIES: [&str; 24] = [
    "aria-activedescendant",
    "aria-autocomplete",
    "aria-checked",
    "aria-colcount",
    "aria-colindex",
    "aria-colspan",
    "aria-expanded",
    "aria-level",
    "aria-multiselectable",
    "aria-orientation",
    "aria-posinset",
    "aria-pressed",
    "aria-readonly",
    "aria-required",
    "aria-rowcount",
    "aria-rowindex",
    "aria-rowspan",
    "aria-selected",
    "aria-setsize",
    "aria-valuemax",
    "aria-valuemin",
    "aria-valuenow",
    "aria-valuetext",
    "aria-sort",
];

/// Non-global ARIA properties each explicit role supports (`S6811`).
const ROLE_SUPPORTED_PROPERTIES: &[(&str, &[&str])] = &[
    ("button", &["aria-expanded", "aria-pressed"]),
    ("checkbox", &["aria-checked", "aria-readonly"]),
    (
        "combobox",
        &["aria-autocomplete", "aria-expanded", "aria-required"],
    ),
    ("heading", &["aria-level"]),
    ("link", &["aria-expanded", "aria-pressed"]),
    (
        "menuitem",
        &[
            "aria-checked",
            "aria-expanded",
            "aria-posinset",
            "aria-setsize",
        ],
    ),
    (
        "option",
        &[
            "aria-checked",
            "aria-posinset",
            "aria-selected",
            "aria-setsize",
        ],
    ),
    ("radio", &["aria-checked", "aria-readonly"]),
    (
        "searchbox",
        &[
            "aria-autocomplete",
            "aria-multiline",
            "aria-readonly",
            "aria-required",
        ],
    ),
    (
        "slider",
        &[
            "aria-orientation",
            "aria-valuemax",
            "aria-valuemin",
            "aria-valuenow",
            "aria-valuetext",
        ],
    ),
    (
        "spinbutton",
        &[
            "aria-orientation",
            "aria-valuemax",
            "aria-valuemin",
            "aria-valuenow",
            "aria-valuetext",
        ],
    ),
    ("switch", &["aria-checked"]),
    (
        "tab",
        &[
            "aria-expanded",
            "aria-posinset",
            "aria-selected",
            "aria-setsize",
        ],
    ),
    (
        "tablist",
        &["aria-level", "aria-multiselectable", "aria-orientation"],
    ),
    (
        "textbox",
        &[
            "aria-autocomplete",
            "aria-multiline",
            "aria-readonly",
            "aria-required",
        ],
    ),
];

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6811_flags_each_unsupported_property_per_role() {
        let slider = jsx_keys("const el = <div role=\"slider\" aria-selected=\"true\"/>;\n");
        assert_eq!(count_key(&slider, "javascript:S6811"), 1);

        let button = jsx_keys(
            "const el = <span role=\"button\" aria-level=\"2\" aria-sort=\"ascending\"/>;\n",
        );
        assert_eq!(count_key(&button, "javascript:S6811"), 2);
    }

    #[test]
    fn s6811_accepts_supported_global_and_unknown_property_names() {
        let supported =
            jsx_keys("const el = <div role=\"slider\" aria-orientation=\"vertical\"/>;\n");
        assert_eq!(count_key(&supported, "javascript:S6811"), 0);

        let global = jsx_keys("const el = <div role=\"slider\" aria-hidden=\"true\"/>;\n");
        assert_eq!(count_key(&global, "javascript:S6811"), 0);

        let unknown_name = jsx_keys("const el = <div role=\"button\" aria-datapoints=\"3\"/>;\n");
        assert_eq!(count_key(&unknown_name, "javascript:S6811"), 0);
    }

    #[test]
    fn s6811_ignores_roles_outside_the_support_table() {
        let note_role = jsx_keys("const el = <div role=\"note\" aria-level=\"2\">x</div>;\n");
        assert_eq!(count_key(&note_role, "javascript:S6811"), 0);
    }
}
