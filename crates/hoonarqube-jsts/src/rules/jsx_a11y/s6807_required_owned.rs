use super::walker::{A11yCollector, attribute_static_value, jsx_attribute_name, jsx_element_tag};
use crate::support::RuleScope;
use oxc_ast::ast::{
    Expression, JSXAttribute, JSXAttributeItem, JSXElement, JSXOpeningElement, ObjectPropertyKind,
    PropertyKey,
};
use oxc_span::GetSpan;

impl A11yCollector<'_> {
    /// `S6807`: every known ARIA role must define its required properties.
    pub(crate) fn check_required_aria_properties(&mut self, element: &JSXElement<'_>) {
        let opening = &element.opening_element;
        let Some(tag) = jsx_element_tag(&opening.name) else {
            return;
        };
        if !DOM_ELEMENTS.contains(&tag) {
            return;
        }
        let Some(role_attribute) = role_attribute(opening) else {
            return;
        };
        let Some(role_value) = attribute_static_value(role_attribute) else {
            return;
        };

        // `isSemanticRoleElement` in jsx-a11y suppresses diagnostics where a
        // native element already supplies the requested role semantics.
        if is_semantic_role_element(tag, opening, role_value) {
            return;
        }

        for role in role_value.to_ascii_lowercase().split(' ') {
            let Some(required) = required_properties(role) else {
                continue;
            };
            if required
                .iter()
                .all(|property| has_property(opening, property))
            {
                continue;
            }
            let message = format!(
                "Elements with the ARIA role \"{role}\" must have the following attributes defined: {}",
                required.join(",")
            );
            self.sink
                .emit_span(RuleScope::Both, "S6807", &message, role_attribute.span());
        }
    }
}

fn role_attribute<'a>(opening: &'a JSXOpeningElement<'a>) -> Option<&'a JSXAttribute<'a>> {
    opening.attributes.iter().find_map(|item| match item {
        JSXAttributeItem::Attribute(attribute)
            if jsx_attribute_name(attribute)
                .is_some_and(|name| name.eq_ignore_ascii_case("role")) =>
        {
            Some(&**attribute)
        }
        _ => None,
    })
}

/// `jsx-ast-utils.getProp`: explicit attributes are case-insensitive and a
/// spread only proves a property when it is an object literal with an
/// identifier key. Dynamic spreads do not prove anything.
fn has_property(opening: &JSXOpeningElement<'_>, name: &str) -> bool {
    opening.attributes.iter().any(|item| match item {
        JSXAttributeItem::Attribute(attribute) => jsx_attribute_name(attribute)
            .is_some_and(|property| property.eq_ignore_ascii_case(name)),
        JSXAttributeItem::SpreadAttribute(spread) => {
            let Expression::ObjectExpression(object) = &spread.argument else {
                return false;
            };
            object.properties.iter().any(|property| {
                let ObjectPropertyKind::ObjectProperty(property) = property else {
                    return false;
                };
                matches!(
                    &property.key,
                    PropertyKey::StaticIdentifier(key)
                        if key.name.as_str().eq_ignore_ascii_case(name)
                )
            })
        }
    })
}

fn required_properties(role: &str) -> Option<&'static [&'static str]> {
    match role {
        "checkbox" | "menuitemcheckbox" | "menuitemradio" | "radio" | "switch" => {
            Some(&["aria-checked"])
        }
        "combobox" => Some(&["aria-controls", "aria-expanded"]),
        "heading" => Some(&["aria-level"]),
        "meter" | "slider" => Some(&["aria-valuenow"]),
        "option" | "treeitem" => Some(&["aria-selected"]),
        "scrollbar" => Some(&["aria-controls", "aria-valuenow"]),
        _ => None,
    }
}

fn is_semantic_role_element(tag: &str, opening: &JSXOpeningElement<'_>, role_value: &str) -> bool {
    let role_matches = |role: &str| role_value == role;
    match tag {
        "input" => match attribute_named_static_value(opening, "type") {
            Some("checkbox") => role_matches("checkbox") || role_matches("switch"),
            Some("radio") => role_matches("radio"),
            Some("range") => role_matches("slider"),
            _ => false,
        },
        "select" => role_matches("combobox"),
        "option" => role_matches("option"),
        "h1" | "h2" | "h3" | "h4" | "h5" | "h6" => role_matches("heading"),
        _ => false,
    }
}

fn attribute_named_static_value<'a>(
    opening: &'a JSXOpeningElement<'a>,
    name: &str,
) -> Option<&'a str> {
    opening.attributes.iter().find_map(|item| match item {
        JSXAttributeItem::Attribute(attribute)
            if jsx_attribute_name(attribute).is_some_and(|property| property == name) =>
        {
            attribute_static_value(attribute)
        }
        _ => None,
    })
}

// aria-query's `dom` map is deliberately narrower than "any lowercase JSX
// tag": custom elements/components must be ignored by this rule.
const DOM_ELEMENTS: &[&str] = &[
    "a",
    "abbr",
    "acronym",
    "address",
    "applet",
    "area",
    "article",
    "aside",
    "audio",
    "b",
    "base",
    "bdi",
    "bdo",
    "big",
    "blink",
    "blockquote",
    "body",
    "br",
    "button",
    "canvas",
    "caption",
    "center",
    "cite",
    "code",
    "col",
    "colgroup",
    "content",
    "data",
    "datalist",
    "dd",
    "del",
    "details",
    "dfn",
    "dialog",
    "dir",
    "div",
    "dl",
    "dt",
    "em",
    "embed",
    "fieldset",
    "figcaption",
    "figure",
    "font",
    "footer",
    "form",
    "frame",
    "frameset",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "head",
    "header",
    "hgroup",
    "hr",
    "html",
    "i",
    "iframe",
    "img",
    "input",
    "ins",
    "kbd",
    "keygen",
    "label",
    "legend",
    "li",
    "link",
    "main",
    "map",
    "mark",
    "marquee",
    "menu",
    "menuitem",
    "meta",
    "meter",
    "nav",
    "noembed",
    "noscript",
    "object",
    "ol",
    "optgroup",
    "option",
    "output",
    "p",
    "param",
    "picture",
    "pre",
    "progress",
    "q",
    "rp",
    "rt",
    "rtc",
    "ruby",
    "s",
    "samp",
    "script",
    "section",
    "select",
    "small",
    "source",
    "spacer",
    "span",
    "strike",
    "strong",
    "style",
    "sub",
    "summary",
    "sup",
    "table",
    "tbody",
    "td",
    "textarea",
    "tfoot",
    "th",
    "thead",
    "time",
    "title",
    "tr",
    "track",
    "tt",
    "u",
    "ul",
    "var",
    "video",
    "wbr",
    "xmp",
];

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6807_requires_role_specific_aria_properties() {
        let checkbox = jsx_keys("const el = <div role=\"checkbox\">Unchecked</div>;\n");
        assert_eq!(count_key(&checkbox, "javascript:S6807"), 1);
        let compliant =
            jsx_keys("const el = <div role=\"checkbox\" aria-checked={checked}>Checked</div>;\n");
        assert_eq!(count_key(&compliant, "javascript:S6807"), 0);

        let combobox = jsx_keys("const el = <div role=\"combobox\" />;\n");
        assert_eq!(count_key(&combobox, "javascript:S6807"), 1);
        let complete = jsx_keys(
            "const el = <div role=\"combobox\" aria-controls=\"list\" aria-expanded={open} />;\n",
        );
        assert_eq!(count_key(&complete, "javascript:S6807"), 0);
    }

    #[test]
    fn s6807_retains_the_legacy_tree_regressions_under_the_aria_contract() {
        let tree_only = jsx_keys("const el = <ul role=\"tree\"/>;\n");
        assert_eq!(count_key(&tree_only, "javascript:S6807"), 0);
        let missing_treeitem =
            jsx_keys("const el = <ul role=\"tree\"><li role=\"treeitem\">Node</li></ul>;\n");
        assert_eq!(count_key(&missing_treeitem, "javascript:S6807"), 1);
    }

    #[test]
    fn s6807_handles_native_dynamic_custom_and_spread_exceptions() {
        let native = jsx_keys(
            "const checkbox = <input type=\"checkbox\" role=\"checkbox\" />;\n\
             const radio = <input type=\"radio\" role=\"radio\" />;\n\
             const slider = <input type=\"range\" role=\"slider\" />;\n\
             const select = <select role=\"combobox\" />;\n\
             const heading = <h1 role=\"heading\" />;\n\
             const option = <option role=\"option\" />;\n",
        );
        assert_eq!(count_key(&native, "javascript:S6807"), 0);

        let dynamic = jsx_keys(
            "const dynamic = <div role={role} />;\n\
             const unknown = <made-up role=\"checkbox\" />;\n\
             const component = <Widget role=\"checkbox\" />;\n\
             const spread = <div role=\"checkbox\" {...props} />;\n",
        );
        assert_eq!(count_key(&dynamic, "javascript:S6807"), 1);
    }

    #[test]
    fn s6807_reports_treeitem_on_role_attribute_with_exact_message_and_range() {
        let report = jsx("const el = <ul role=\"tree\"><li role=\"treeitem\">Node</li></ul>;\n");
        let issue = report
            .issues
            .iter()
            .find(|issue| issue.rule_key == "javascript:S6807")
            .expect("treeitem requires aria-selected");
        assert_eq!(
            issue.message,
            "Elements with the ARIA role \"treeitem\" must have the following attributes defined: aria-selected"
        );
        assert_eq!(issue.range.start.line, 1);
        assert_eq!(issue.range.start.column, 31);
        assert_eq!(issue.range.end.line, 1);
        assert_eq!(issue.range.end.column, 46);
    }
}
