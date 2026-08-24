// Family walker for 'jsx_a11y' (generated).
use crate::context::AnalysisContext;
use crate::support::{IssueSink, LineIndex, RuleScope};
use crate::{
    IMPLICIT_ROLES, INTERACTIVE_ROLES, JstsLanguage, NON_INTERACTIVE_ROLES, jsx_has_attribute,
    language_tag_is_valid,
};
use hoonarqube_ir::Issue;
use oxc_ast::ast::{
    Expression, JSXAttribute, JSXAttributeItem, JSXAttributeName, JSXAttributeValue, JSXElement,
    JSXElementName, JSXOpeningElement, JSXText,
};
use oxc_ast_visit::Visit;
use oxc_ast_visit::walk::walk_jsx_element;
use oxc_span::{GetSpan, Span};
use std::collections::BTreeSet;

/// All Batch4 JSX accessibility checks in one traversal (groups A1-A3).
pub(crate) fn check_jsx_accessibility_rules(
    program: &oxc_ast::ast::Program<'_>,
    index: &LineIndex,
    language: JstsLanguage,
) -> Vec<Issue> {
    let mut collector = A11yCollector {
        sink: IssueSink {
            index,
            language,
            issues: Vec::new(),
        },
    };
    collector.visit_program(program);
    collector.sink.issues
}

/// Accessibility rules in one JSX traversal (groups A1-A3).
pub(crate) struct A11yCollector<'index> {
    pub(crate) sink: IssueSink<'index>,
}

impl Visit<'_> for A11yCollector<'_> {
    fn visit_jsx_element(&mut self, it: &JSXElement<'_>) {
        self.check_alt_text(it);
        self.check_mouse_keyboard_pair(it);
        self.check_iframe_title(it);
        self.check_media_captions(it);
        self.check_html_lang(it);
        self.check_table_facts(it);
        self.check_object_alternative(it);
        self.check_accesskey(it);
        self.check_tab_index_value(it);
        self.check_heading_content(it);
        self.check_redundant_alt(it);
        self.check_anchor_content(it);
        self.check_role_duplicates(it);
        self.check_abstract_role(it);
        self.check_aria_values(it);
        self.check_required_owned(it);
        self.check_supported_properties(it);
        self.check_activedescendant_focusable(it);
        self.check_allowed_roles(it);
        self.check_aria_hidden_focusable(it);
        self.check_autocomplete_value(it);
        self.check_noninteractive_with_interactive_role(it);
        self.check_interactive_with_noninteractive_role(it);
        self.check_interactive_role_focusable(it);
        self.check_anchor_click_without_href(it);
        self.check_noninteractive_tab_index(it);
        self.check_noninteractive_handlers(it);
        self.check_click_keyboard_pair(it);
        self.check_label_association(it);
        walk_jsx_element(self, it);
    }
}

impl A11yCollector<'_> {
    /// `S1077`: images, areas, objects, and image inputs need alt text.
    pub(crate) fn check_alt_text(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag) {
            return;
        }
        let needs_alt = match tag {
            "img" | "area" | "object" => true,
            "input" => {
                jsx_find_attribute(&element.opening_element, "type")
                    .and_then(attribute_static_value)
                    == Some("image")
            }
            _ => false,
        };
        if !needs_alt || jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        if jsx_find_attribute(&element.opening_element, "alt").is_none() {
            let message = format!("Add an 'alt' attribute to this <{tag}> element.");
            self.sink.emit_span(
                RuleScope::Both,
                "S1077",
                &message,
                element.opening_element.span(),
            );
        }
    }

    /// `S1082`: mouse-over/out handlers need focus/blur counterparts.
    pub(crate) fn check_mouse_keyboard_pair(&mut self, element: &JSXElement<'_>) {
        if jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        for (mouse, keyboard) in [("onMouseOver", "onFocus"), ("onMouseOut", "onBlur")] {
            let Some(mouse_attribute) = jsx_find_attribute(&element.opening_element, mouse) else {
                continue;
            };
            if jsx_find_attribute(&element.opening_element, keyboard).is_none() {
                let message =
                    format!("Add the '{keyboard}' handler to pair with this '{mouse}' handler.");
                self.sink
                    .emit_span(RuleScope::Both, "S1082", &message, mouse_attribute.span());
            }
        }
    }

    /// `S1090`: iframes need titles.
    pub(crate) fn check_iframe_title(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("iframe")
            || jsx_has_spread_attribute(&element.opening_element)
            || jsx_find_attribute(&element.opening_element, "title").is_some()
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S1090",
            "Add a 'title' attribute to this <iframe>.",
            element.opening_element.span(),
        );
    }

    /// `S4084`: audio and video elements need caption tracks.
    pub(crate) fn check_media_captions(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !matches!(tag, "audio" | "video") {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        if !facts.track_captions {
            self.sink.emit_span(
                RuleScope::Both,
                "S4084",
                "Provide captions for this media element with a <track kind=\"captions\"> descendant.",
                element.opening_element.span(),
            );
        }
    }

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

    /// `S5256`, `S5257`, and `S5260`: header structure inside tables.
    pub(crate) fn check_table_facts(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("table") {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        let presentation_role = explicit_role(&element.opening_element)
            .is_some_and(|role| role == "presentation" || role == "none");
        if facts.table_markers != TableMarkers::Headers {
            self.sink.emit_span(
                RuleScope::Both,
                "S5256",
                "Add header cells (<th> or <thead>) to this table.",
                element.opening_element.span(),
            );
            if facts.table_markers == TableMarkers::Plain && !presentation_role {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S5257",
                    "Mark this layout table with role=\"presentation\" or give it real headers.",
                    element.opening_element.span(),
                );
            }
        }
        for (span, tokens) in &facts.header_references {
            if tokens.iter().any(|token| !facts.header_ids.contains(token)) {
                self.sink.emit_span(
                    RuleScope::Both,
                    "S5260",
                    "This 'headers' reference does not match any <th id> in the table.",
                    *span,
                );
            }
        }
    }

    /// `S5264`: object elements need a text alternative.
    pub(crate) fn check_object_alternative(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("object")
            || jsx_has_spread_attribute(&element.opening_element)
        {
            return;
        }
        let labeled = ["aria-label", "aria-labelledby", "title"]
            .iter()
            .any(|name| jsx_find_attribute(&element.opening_element, name).is_some());
        if labeled {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        if !facts.has_visible_text {
            self.sink.emit_span(
                RuleScope::Both,
                "S5264",
                "Provide a text alternative for this <object> element.",
                element.opening_element.span(),
            );
        }
    }

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

    /// `S6850`: headings must have text content or a label.
    pub(crate) fn check_heading_content(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !matches!(tag, "h1" | "h2" | "h3" | "h4" | "h5" | "h6") {
            return;
        }
        let labeled = ["aria-label", "aria-labelledby", "title"]
            .iter()
            .any(|name| jsx_find_attribute(&element.opening_element, name).is_some());
        if labeled {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        if !facts.has_visible_text {
            self.sink.emit_span(
                RuleScope::Both,
                "S6850",
                "This heading has no text content.",
                element.opening_element.span(),
            );
        }
    }

    /// `S6851`: alt text repeating the file name or a filler word.
    pub(crate) fn check_redundant_alt(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("img") {
            return;
        }
        let Some(alt_attribute) = jsx_find_attribute(&element.opening_element, "alt") else {
            return;
        };
        let Some(alt) = attribute_static_value(alt_attribute) else {
            return;
        };
        let normalized = alt.trim().to_lowercase();
        let source_stem = jsx_find_attribute(&element.opening_element, "src")
            .and_then(attribute_static_value)
            .and_then(|source| source.rsplit('/').next())
            .and_then(|name| name.rsplit_once('.').map(|(stem, _)| stem))
            .map(str::to_lowercase);
        if REDUNDANT_ALT_WORDS.contains(&normalized.as_str())
            || source_stem.as_deref() == Some(normalized.as_str())
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6851",
                "Redundant 'alt' text; describe the image purpose instead.",
                alt_attribute.span(),
            );
        }
    }

    /// `S6827`: anchors without `href` still need accessible text.
    pub(crate) fn check_anchor_content(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("a")
            || jsx_find_attribute(&element.opening_element, "href").is_some()
        {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        if !facts.has_visible_text {
            self.sink.emit_span(
                RuleScope::Both,
                "S6827",
                "Give this <a> an 'href' or accessible text content.",
                element.opening_element.span(),
            );
        }
    }

    /// `S6822` and `S6819`: explicit roles duplicating the implicit ones.
    pub(crate) fn check_role_duplicates(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag) {
            return;
        }
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        if implicit_role(tag, &element.opening_element) != Some(role) {
            return;
        }
        let Some(role_attribute) = jsx_find_attribute(&element.opening_element, "role") else {
            return;
        };
        self.sink.emit_span(
            RuleScope::Both,
            "S6822",
            "This 'role' duplicates the element's implicit role; remove it.",
            role_attribute.span(),
        );
        self.sink.emit_span(
            RuleScope::Both,
            "S6819",
            "Remove this explicit 'role'; the element already has these semantics implicitly.",
            role_attribute.span(),
        );
    }

    /// `S6821`: abstract roles cannot be used on elements.
    pub(crate) fn check_abstract_role(&mut self, element: &JSXElement<'_>) {
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        if !ABSTRACT_ROLES.contains(&role) {
            return;
        }
        let message = format!("'{role}' is an abstract role and cannot be used on elements.");
        let role_attribute = jsx_find_attribute(&element.opening_element, "role");
        self.sink.emit_span(
            RuleScope::Both,
            "S6821",
            &message,
            role_attribute.map_or(element.span(), GetSpan::span),
        );
    }

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

    /// `S6807`: roles with required owned descendants.
    pub(crate) fn check_required_owned(&mut self, element: &JSXElement<'_>) {
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        let Some((_, required)) = ROLE_REQUIRED_CHILDREN
            .iter()
            .find(|(name, _)| *name == role)
        else {
            return;
        };
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        let owns_required = facts
            .descendant_roles
            .iter()
            .any(|descendant| required.contains(&descendant.as_str()));
        if !owns_required {
            let message = format!(
                "A '{role}' must own a '{}' descendant to be complete.",
                required[0]
            );
            let role_attribute = jsx_find_attribute(&element.opening_element, "role");
            self.sink.emit_span(
                RuleScope::Both,
                "S6807",
                &message,
                role_attribute.map_or(element.span(), GetSpan::span),
            );
        }
    }

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

    /// `S6823`: `aria-activedescendant` requires a tab index.
    pub(crate) fn check_activedescendant_focusable(&mut self, element: &JSXElement<'_>) {
        if jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        let Some(active_attribute) =
            jsx_find_attribute(&element.opening_element, "aria-activedescendant")
        else {
            return;
        };
        if ["tabIndex", "tabindex"]
            .iter()
            .any(|name| jsx_find_attribute(&element.opening_element, name).is_some())
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6823",
            "Elements with 'aria-activedescendant' must carry 'tabIndex'.",
            active_attribute.span(),
        );
    }

    /// `S6824`: explicit roles must be permitted on the carrying element.
    pub(crate) fn check_allowed_roles(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag) || jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        let Some((_, allowed)) = ALLOWED_ROLES_BY_ELEMENT
            .iter()
            .find(|(name, _)| *name == tag)
        else {
            return;
        };
        if !allowed.contains(&role) {
            let message = format!("'{role}' is not an allowed role for <{tag}> elements.");
            self.sink.emit_span(
                RuleScope::Both,
                "S6824",
                &message,
                element.opening_element.span(),
            );
        }
    }

    /// `S6825`: focusable elements cannot be hidden from assistive tech.
    pub(crate) fn check_aria_hidden_focusable(&mut self, element: &JSXElement<'_>) {
        if jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        let Some(hidden_attribute) = jsx_find_attribute(&element.opening_element, "aria-hidden")
        else {
            return;
        };
        if attribute_static_value(hidden_attribute) != Some("true") {
            return;
        }
        let intrinsically_focusable = match jsx_element_tag(&element.opening_element.name) {
            Some(tag) if jsx_tag_is_intrinsic(tag) => {
                is_interactive_element(tag, &element.opening_element)
            }
            _ => false,
        };
        let tabbable = ["tabIndex", "tabindex"].iter().any(|name| {
            jsx_find_attribute(&element.opening_element, name)
                .and_then(attribute_integer_value)
                .is_some_and(|value| value >= 0)
        });
        if intrinsically_focusable || tabbable {
            self.sink.emit_span(
                RuleScope::Both,
                "S6825",
                "Do not hide this focusable element with 'aria-hidden=\"true\"'.",
                hidden_attribute.span(),
            );
        }
    }

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

    /// `S6842`: interactive roles belong on natively interactive elements.
    pub(crate) fn check_noninteractive_with_interactive_role(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag)
            || jsx_has_spread_attribute(&element.opening_element)
            || is_interactive_element(tag, &element.opening_element)
        {
            return;
        }
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        if is_interactive_role(role) {
            let message = format!(
                "Replace this <{tag}> with an interactive element or remove the '{role}' role."
            );
            let role_attribute = jsx_find_attribute(&element.opening_element, "role");
            self.sink.emit_span(
                RuleScope::Both,
                "S6842",
                &message,
                role_attribute.map_or(element.span(), GetSpan::span),
            );
        }
    }

    /// `S6843`: interactive elements must not take structural roles.
    pub(crate) fn check_interactive_with_noninteractive_role(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag)
            || jsx_has_spread_attribute(&element.opening_element)
            || !is_interactive_element(tag, &element.opening_element)
        {
            return;
        }
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        if is_non_interactive_role(role) {
            let message = format!("Interactive <{tag}> elements cannot take the '{role}' role.");
            let role_attribute = jsx_find_attribute(&element.opening_element, "role");
            self.sink.emit_span(
                RuleScope::Both,
                "S6843",
                &message,
                role_attribute.map_or(element.span(), GetSpan::span),
            );
        }
    }

    /// `S6852`: elements with an interactive role must be focusable.
    pub(crate) fn check_interactive_role_focusable(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag) || jsx_has_spread_attribute(&element.opening_element) {
            return;
        }
        let Some(role) = explicit_role(&element.opening_element) else {
            return;
        };
        if !is_interactive_role(role)
            || is_interactive_element(tag, &element.opening_element)
            || ["tabIndex", "tabindex"]
                .iter()
                .any(|name| jsx_find_attribute(&element.opening_element, name).is_some())
        {
            return;
        }
        let message =
            format!("Elements with the '{role}' role must be focusable; add a 'tabIndex'.");
        let role_attribute = jsx_find_attribute(&element.opening_element, "role");
        self.sink.emit_span(
            RuleScope::Both,
            "S6852",
            &message,
            role_attribute.map_or(element.span(), GetSpan::span),
        );
    }

    /// `S6844`: click handlers on anchors without `href`.
    pub(crate) fn check_anchor_click_without_href(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("a")
            || jsx_has_spread_attribute(&element.opening_element)
            || jsx_find_attribute(&element.opening_element, "href").is_some()
        {
            return;
        }
        if jsx_find_attribute(&element.opening_element, "onClick").is_some() {
            self.sink.emit_span(
                RuleScope::Both,
                "S6844",
                "Add an 'href' to this <a> or use a <button> for this action.",
                element.opening_element.span(),
            );
        }
    }

    /// `S6845`: positive tab indices belong on interactive elements.
    pub(crate) fn check_noninteractive_tab_index(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag)
            || jsx_has_spread_attribute(&element.opening_element)
            || is_interactive_element(tag, &element.opening_element)
            || jsx_find_attribute(&element.opening_element, "aria-activedescendant").is_some()
        {
            return;
        }
        let Some(index_attribute) = ["tabIndex", "tabindex"]
            .iter()
            .find_map(|name| jsx_find_attribute(&element.opening_element, name))
        else {
            return;
        };
        let focusable_by_role =
            explicit_role(&element.opening_element).is_some_and(is_interactive_role);
        if !focusable_by_role
            && attribute_integer_value(index_attribute).is_some_and(|value| value >= 0)
        {
            self.sink.emit_span(
                RuleScope::Both,
                "S6845",
                "Remove this positive 'tabIndex'; make the element properly interactive instead.",
                index_attribute.span(),
            );
        }
    }

    /// `S6847`: interaction handlers belong on interactive elements.
    pub(crate) fn check_noninteractive_handlers(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag)
            || jsx_has_spread_attribute(&element.opening_element)
            || is_interactive_element(tag, &element.opening_element)
            || explicit_role(&element.opening_element).is_some_and(is_interactive_role)
        {
            return;
        }
        for item in &element.opening_element.attributes {
            let JSXAttributeItem::Attribute(attribute) = item else {
                continue;
            };
            let Some(name) = jsx_attribute_name(attribute) else {
                continue;
            };
            if INTERACTION_HANDLERS.contains(&name) {
                let message = format!("Move this '{name}' handler to an interactive element.");
                self.sink
                    .emit_span(RuleScope::Both, "S6847", &message, attribute.span());
            }
        }
    }

    /// `S6848`: click handlers need keyboard counterparts on
    /// non-interactive elements.
    pub(crate) fn check_click_keyboard_pair(&mut self, element: &JSXElement<'_>) {
        let Some(tag) = jsx_element_tag(&element.opening_element.name) else {
            return;
        };
        if !jsx_tag_is_intrinsic(tag)
            || jsx_has_spread_attribute(&element.opening_element)
            || is_interactive_element(tag, &element.opening_element)
            || explicit_role(&element.opening_element).is_some_and(is_interactive_role)
        {
            return;
        }
        let Some(click_attribute) = jsx_find_attribute(&element.opening_element, "onClick") else {
            return;
        };
        if KEYBOARD_HANDLERS
            .iter()
            .any(|name| jsx_find_attribute(&element.opening_element, name).is_some())
        {
            return;
        }
        self.sink.emit_span(
            RuleScope::Both,
            "S6848",
            "Add a keyboard handler ('onKeyDown', 'onKeyPress', or 'onKeyUp') to pair with this 'onClick'.",
            click_attribute.span(),
        );
    }

    /// `S6853`: labels need text and a control association.
    pub(crate) fn check_label_association(&mut self, element: &JSXElement<'_>) {
        if jsx_element_tag(&element.opening_element.name) != Some("label")
            || jsx_has_spread_attribute(&element.opening_element)
        {
            return;
        }
        let mut facts = SubtreeFacts::default();
        facts.visit_jsx_element(element);
        let labeled = ["aria-label", "aria-labelledby"]
            .iter()
            .any(|name| jsx_find_attribute(&element.opening_element, name).is_some());
        let associated = jsx_find_attribute(&element.opening_element, "htmlFor").is_some()
            || facts.labelable_controls > 0;
        if (!facts.has_visible_text && !labeled) || !associated {
            self.sink.emit_span(
                RuleScope::Both,
                "S6853",
                "Associate this <label> with a form control and give it text content.",
                element.opening_element.span(),
            );
        }
    }
}

/// Keyboard handlers that pair with `onClick` for `S6848`.
pub(crate) const KEYBOARD_HANDLERS: [&str; 3] = ["onKeyDown", "onKeyPress", "onKeyUp"];

/// Interaction handler props the matrix rules consider (`S6847`).
pub(crate) const INTERACTION_HANDLERS: [&str; 8] = [
    "onChange",
    "onClick",
    "onDoubleClick",
    "onKeyDown",
    "onKeyPress",
    "onKeyUp",
    "onMouseDown",
    "onMouseUp",
];

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

/// Roles each restrictive element permits (`S6824`); elements outside this
/// table accept any explicit role.
pub(crate) const ALLOWED_ROLES_BY_ELEMENT: &[(&str, &[&str])] = &[
    ("article", &["article", "feed", "none", "presentation"]),
    (
        "aside",
        &["complementary", "feed", "none", "presentation", "search"],
    ),
    ("caption", &["none", "presentation"]),
    ("code", &["none", "presentation"]),
    ("dd", &["none", "presentation"]),
    ("dfn", &["none", "presentation"]),
    ("dialog", &["alertdialog", "dialog"]),
    ("dt", &["listitem", "none", "presentation"]),
    ("footer", &["contentinfo", "group", "none", "presentation"]),
    ("form", &["form", "none", "presentation", "search"]),
    ("header", &["banner", "group", "none", "presentation"]),
    ("h1", &["heading", "none", "presentation"]),
    ("h2", &["heading", "none", "presentation"]),
    ("h3", &["heading", "none", "presentation"]),
    ("h4", &["heading", "none", "presentation"]),
    ("h5", &["heading", "none", "presentation"]),
    ("h6", &["heading", "none", "presentation"]),
    (
        "li",
        &[
            "listitem",
            "menuitem",
            "menuitemcheckbox",
            "menuitemradio",
            "none",
            "option",
            "presentation",
            "row",
            "tab",
            "treeitem",
        ],
    ),
    ("main", &["main", "none", "presentation"]),
    (
        "nav",
        &[
            "menu",
            "menubar",
            "navigation",
            "none",
            "presentation",
            "tablist",
        ],
    ),
    ("ol", &LIST_CONTAINER_ROLES),
    (
        "section",
        &[
            "alert",
            "alertdialog",
            "application",
            "banner",
            "complementary",
            "contentinfo",
            "dialog",
            "document",
            "feed",
            "form",
            "main",
            "marquee",
            "navigation",
            "none",
            "note",
            "presentation",
            "region",
            "search",
            "status",
        ],
    ),
    ("tbody", &["rowgroup"]),
    ("td", &["cell", "gridcell", "none", "presentation"]),
    ("tfoot", &["rowgroup"]),
    ("th", &["columnheader", "none", "presentation", "rowheader"]),
    ("thead", &["rowgroup"]),
    ("tr", &["none", "presentation", "row"]),
    ("ul", &LIST_CONTAINER_ROLES),
];

/// Roles a list container (`ol`/`ul`) may take (`S6824`).
pub(crate) const LIST_CONTAINER_ROLES: [&str; 9] = [
    "group",
    "list",
    "menu",
    "menubar",
    "none",
    "presentation",
    "tablist",
    "toolbar",
    "tree",
];

/// Global ARIA properties valid on every role (`S6811` exemptions).
pub(crate) const GLOBAL_ARIA_PROPERTIES: [&str; 18] = [
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
pub(crate) const KNOWN_ARIA_PROPERTIES: [&str; 24] = [
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
pub(crate) const ROLE_SUPPORTED_PROPERTIES: &[(&str, &[&str])] = &[
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

/// Roles that require owned descendant roles (`S6807`).
pub(crate) const ROLE_REQUIRED_CHILDREN: &[(&str, &[&str])] = &[
    ("grid", &["row"]),
    ("list", &["listitem"]),
    ("listbox", &["option"]),
    ("menu", &["menuitem", "menuitemcheckbox", "menuitemradio"]),
    ("row", &["cell", "columnheader", "rowheader"]),
    ("table", &["row"]),
    ("tablist", &["tab"]),
    ("tree", &["treeitem"]),
];

/// Numeric ARIA attributes validated as non-negative integers (`S6793`).
pub(crate) const NUMERIC_ARIA_PROPERTIES: [&str; 3] =
    ["aria-level", "aria-posinset", "aria-setsize"];

/// Token-set ARIA attributes and their accepted literal values (`S6793`);
/// `"true"`/`"false"` are valid for every entry.
pub(crate) const TOKEN_ARIA_PROPERTIES: &[(&str, &[&str])] = &[
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
pub(crate) const BOOLEAN_ARIA_PROPERTIES: [&str; 13] = [
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

// ===== Batch4 groups A1-A3: JSX accessibility rules =====
//
// Table-driven jsx-a11y checks over one JSX walk: `S1077` (alt text),
// `S1082` (mouse handlers), `S1090` (iframe title), `S4084` (media
// captions), `S5254` (html lang), `S5256`/`S5257`/`S5260` (table
// structure), `S5264` (object alternative), `S6846` (accesskey), and
// `S6841` (tabIndex values). Groups A2/A3 add the role and interaction
// matrices.

/// Abstract roles that must never reach an element's `role` attribute.
pub(crate) const ABSTRACT_ROLES: [&str; 12] = [
    "command",
    "composite",
    "input",
    "landmark",
    "range",
    "roletype",
    "section",
    "sectionhead",
    "select",
    "structure",
    "widget",
    "window",
];

/// Redundant image alt texts (`S6851`).
pub(crate) const REDUNDANT_ALT_WORDS: [&str; 6] =
    ["image", "photo", "picture", "grafik", "bild", "logo"];

/// Which header affordances a table subtree provides.
#[derive(Clone, Copy, Default, PartialEq)]
pub(crate) enum TableMarkers {
    #[default]
    Plain,
    Caption,
    Headers,
}

/// Facts gathered from one subtree for the table, media, and text rules.
#[derive(Default)]
pub(crate) struct SubtreeFacts {
    pub(crate) table_markers: TableMarkers,
    pub(crate) track_captions: bool,
    pub(crate) has_visible_text: bool,
    pub(crate) header_ids: BTreeSet<String>,
    pub(crate) header_references: Vec<(Span, Vec<String>)>,
    pub(crate) descendant_roles: BTreeSet<String>,
    pub(crate) labelable_controls: u32,
}

impl Visit<'_> for SubtreeFacts {
    fn visit_jsx_element(&mut self, it: &JSXElement<'_>) {
        if let Some(tag) = jsx_element_tag(&it.opening_element.name) {
            match tag {
                "th" | "thead" => self.table_markers = TableMarkers::Headers,
                "caption" => {
                    if self.table_markers == TableMarkers::Plain {
                        self.table_markers = TableMarkers::Caption;
                    }
                }
                "track"
                    if jsx_find_attribute(&it.opening_element, "kind")
                        .and_then(attribute_static_value)
                        == Some("captions") =>
                {
                    self.track_captions = true;
                }
                "button" | "input" | "meter" | "output" | "progress" | "select" | "textarea" => {
                    self.labelable_controls += 1;
                }
                _ => {}
            }
            if tag == "th"
                && let Some(id_attribute) = jsx_find_attribute(&it.opening_element, "id")
                && let Some(value) = attribute_static_value(id_attribute)
            {
                self.header_ids.insert(value.to_string());
            }
            if matches!(tag, "td" | "th")
                && let Some(headers_attribute) = jsx_find_attribute(&it.opening_element, "headers")
                && let Some(value) = attribute_static_value(headers_attribute)
            {
                let tokens: Vec<String> = value.split_whitespace().map(str::to_string).collect();
                if !tokens.is_empty() {
                    self.header_references
                        .push((headers_attribute.span(), tokens));
                }
            }
            if let Some(role) = resolved_role(tag, &it.opening_element) {
                self.descendant_roles.insert(role);
            }
        }
        walk_jsx_element(self, it);
    }

    fn visit_jsx_text(&mut self, it: &JSXText<'_>) {
        if !it.value.trim().is_empty() {
            self.has_visible_text = true;
        }
    }
}

/// Tag name of a JSX element when spelled as a plain identifier (`div`,
/// `Widget`); namespaced, member, and `this` names have none.
pub(crate) fn jsx_element_tag<'a>(name: &'a JSXElementName<'a>) -> Option<&'a str> {
    match name {
        JSXElementName::Identifier(identifier) => Some(identifier.name.as_str()),
        JSXElementName::IdentifierReference(reference) => Some(&reference.name),
        _ => None,
    }
}

/// Whether a tag starts lowercase (intrinsic HTML/SVG spelling).
pub(crate) fn jsx_tag_is_intrinsic(tag: &str) -> bool {
    tag.starts_with(|ch: char| ch.is_ascii_lowercase())
}

/// First attribute with the given name on an opening tag, if any.
pub(crate) fn jsx_find_attribute<'a>(
    opening: &'a JSXOpeningElement<'a>,
    name: &str,
) -> Option<&'a JSXAttribute<'a>> {
    opening.attributes.iter().find_map(|item| match item {
        JSXAttributeItem::Attribute(attribute) if jsx_attribute_name(attribute) == Some(name) => {
            Some(&**attribute)
        }
        _ => None,
    })
}

/// Whether the opening tag carries a spread attribute (unknown props).
pub(crate) fn jsx_has_spread_attribute(opening: &JSXOpeningElement<'_>) -> bool {
    opening
        .attributes
        .iter()
        .any(|item| matches!(item, JSXAttributeItem::SpreadAttribute(_)))
}

/// Explicit single-token `role` attribute value, if any.
pub(crate) fn explicit_role<'x>(opening: &'x JSXOpeningElement<'x>) -> Option<&'x str> {
    let value = attribute_static_value(jsx_find_attribute(opening, "role")?)?;
    value.split_whitespace().last()
}

/// Tag name of a JSX attribute (`ref`, `children`, ...); namespaced names
/// (`xlink:href`) have no plain name.
pub(crate) fn jsx_attribute_name<'a>(attribute: &'a JSXAttribute<'a>) -> Option<&'a str> {
    match &attribute.name {
        JSXAttributeName::Identifier(identifier) => Some(identifier.name.as_str()),
        JSXAttributeName::NamespacedName(_) => None,
    }
}

/// Integer content of an attribute value: numeric literals or strings that
/// parse as integers.
pub(crate) fn attribute_integer_value(attribute: &JSXAttribute<'_>) -> Option<i64> {
    match attribute.value.as_ref()? {
        JSXAttributeValue::StringLiteral(literal) => literal.value.trim().parse().ok(),
        JSXAttributeValue::ExpressionContainer(container) => {
            match container.expression.as_expression()? {
                Expression::NumericLiteral(literal) => {
                    literal.raw.as_ref().and_then(|raw| raw.trim().parse().ok())
                }
                _ => None,
            }
        }
        _ => None,
    }
}

/// Static string content of an attribute value, if it is a string literal
/// or a container wrapping one.
pub(crate) fn attribute_static_value<'a>(attribute: &'a JSXAttribute<'a>) -> Option<&'a str> {
    match attribute.value.as_ref()? {
        JSXAttributeValue::StringLiteral(literal) => Some(literal.value.as_str()),
        JSXAttributeValue::ExpressionContainer(container) => {
            match container.expression.as_expression()? {
                Expression::StringLiteral(literal) => Some(literal.value.as_str()),
                _ => None,
            }
        }
        _ => None,
    }
}

/// Implicit ARIA role of an intrinsic tag, refined by `a[href]` and
/// `input[type]`.
pub(crate) fn implicit_role(tag: &str, opening: &JSXOpeningElement) -> Option<&'static str> {
    match tag {
        "a" | "area" => jsx_find_attribute(opening, "href").map(|_| "link"),
        "input" => {
            let input_type = jsx_find_attribute(opening, "type").and_then(attribute_static_value);
            Some(match input_type {
                Some("checkbox") => "checkbox",
                Some("radio") => "radio",
                Some("button" | "image") => "button",
                Some("number") => "spinbutton",
                Some("range") => "slider",
                Some("search") => "searchbox",
                _ => "textbox",
            })
        }
        _ => IMPLICIT_ROLES
            .iter()
            .find(|(name, _)| *name == tag)
            .map(|(_, role)| *role),
    }
}

/// Whether an intrinsic element is natively interactive (interaction-matrix
/// rules).
pub(crate) fn is_interactive_element(tag: &str, opening: &JSXOpeningElement<'_>) -> bool {
    match tag {
        "a" | "area" => jsx_find_attribute(opening, "href").is_some(),
        "audio" | "video" => jsx_has_attribute(opening, "controls"),
        "img" | "object" => jsx_has_attribute(opening, "usemap"),
        "input" => attribute_named_static_value(opening, "type") != Some("hidden"),
        "button" | "details" | "embed" | "iframe" | "label" | "menu" | "menuitem" | "select"
        | "summary" | "textarea" => true,
        _ => false,
    }
}

/// Static string value of the named attribute, if it carries one.
pub(crate) fn attribute_named_static_value<'x>(
    opening: &'x JSXOpeningElement<'x>,
    name: &str,
) -> Option<&'x str> {
    jsx_find_attribute(opening, name).and_then(attribute_static_value)
}

/// Whether an explicit role makes an element interactive.
pub(crate) fn is_interactive_role(role: &str) -> bool {
    INTERACTIVE_ROLES.contains(&role)
}

/// Whether an explicit role is a purely structural or document role.
pub(crate) fn is_non_interactive_role(role: &str) -> bool {
    NON_INTERACTIVE_ROLES.contains(&role)
}

/// Effective role of an element: explicit attribute value or the tag's
/// implicit role.
pub(crate) fn resolved_role(tag: &str, opening: &JSXOpeningElement) -> Option<String> {
    explicit_role(opening)
        .map(str::to_string)
        .or_else(|| implicit_role(tag, opening).map(str::to_string))
}

pub(crate) fn run(ctx: &AnalysisContext) -> Vec<Issue> {
    check_jsx_accessibility_rules(ctx.program, ctx.index, ctx.language)
}

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn alt_text_is_required_on_replaced_elements() {
        let missing = jsx_keys("const el = <img src=\"a.png\"/>;\n");
        assert_eq!(count_key(&missing, "javascript:S1077"), 1);

        let present = jsx_keys("const el = <img src=\"a.png\" alt=\"Chart\"/>;\n");
        assert_eq!(count_key(&present, "javascript:S1077"), 0);

        let image_input = jsx_keys("const el = <input type=\"image\"/>;\n");
        assert_eq!(count_key(&image_input, "javascript:S1077"), 1);

        let text_input = jsx_keys("const el = <input type=\"text\"/>;\n");
        assert_eq!(count_key(&text_input, "javascript:S1077"), 0);

        let spread_props = jsx_keys("const el = <img {...props}/>;\n");
        assert_eq!(count_key(&spread_props, "javascript:S1077"), 0);
    }

    #[test]
    fn mouse_handlers_need_focus_counterparts() {
        let alone = jsx_keys("const el = <div onMouseOver={hover}/>;\n");
        assert_eq!(count_key(&alone, "javascript:S1082"), 1);

        let paired = jsx_keys("const el = <div onMouseOver={hover} onFocus={focus}/>\n;\n");
        assert_eq!(count_key(&paired, "javascript:S1082"), 0);

        let out_blur = jsx_keys("const el = <div onMouseOut={leave} onBlur={blur}/>\n;\n");
        assert_eq!(count_key(&out_blur, "javascript:S1082"), 0);
    }

    #[test]
    fn iframes_require_titles() {
        let bare = jsx_keys("const el = <iframe/>;\n");
        assert_eq!(count_key(&bare, "javascript:S1090"), 1);

        let titled = jsx_keys("const el = <iframe title=\"Map\"/>\n;\n");
        assert_eq!(count_key(&titled, "javascript:S1090"), 0);
    }

    #[test]
    fn media_elements_need_caption_tracks() {
        let bare_video = jsx_keys("const el = <video src=\"a.mp4\"/>;\n");
        assert_eq!(count_key(&bare_video, "javascript:S4084"), 1);

        let captioned =
            jsx_keys("const el = <video src=\"a.mp4\"><track kind=\"captions\"/></video>;\n");
        assert_eq!(count_key(&captioned, "javascript:S4084"), 0);

        let bare_audio = jsx_keys("const el = <audio src=\"a.mp3\"/>;\n");
        assert_eq!(count_key(&bare_audio, "javascript:S4084"), 1);
    }

    #[test]
    fn html_elements_need_valid_language_tags() {
        let missing = jsx_keys("const el = <html><body/></html>;\n");
        assert_eq!(count_key(&missing, "javascript:S5254"), 1);

        let valid_region = jsx_keys("const el = <html lang=\"de-DE\"><body/></html>;\n");
        assert_eq!(count_key(&valid_region, "javascript:S5254"), 0);

        let numeric_primary = jsx_keys("const el = <html lang=\"123\"><body/></html>;\n");
        assert_eq!(count_key(&numeric_primary, "javascript:S5254"), 1);

        let too_short = jsx_keys("const el = <html lang=\"e\"><body/></html>;\n");
        assert_eq!(count_key(&too_short, "javascript:S5254"), 1);
    }

    #[test]
    fn tables_need_header_cells() {
        let headerless = jsx_keys("const el = <table><tr><td>x</td></tr></table>;\n");
        assert_eq!(count_key(&headerless, "javascript:S5256"), 1);

        let headed = jsx_keys("const el = <table><tr><th>x</th></tr></table>;\n");
        assert_eq!(count_key(&headed, "javascript:S5256"), 0);
    }

    #[test]
    fn layout_tables_need_presentation_role() {
        let plain_layout = jsx_keys("const el = <table><tr><td>x</td></tr></table>;\n");
        assert_eq!(count_key(&plain_layout, "javascript:S5257"), 1);

        let captioned =
            jsx_keys("const el = <table><caption>t</caption><tr><td>x</td></tr></table>;\n");
        assert_eq!(count_key(&captioned, "javascript:S5257"), 0);

        let presentation =
            jsx_keys("const el = <table role=\"presentation\"><tr><td>x</td></tr></table>;\n");
        assert_eq!(count_key(&presentation, "javascript:S5257"), 0);
    }

    #[test]
    fn header_references_must_match_th_ids() {
        let broken_reference = jsx_keys(
            "const el = <table><tr><th id=\"a\"/><td headers=\"a\"/></tr><tr><td headers=\"zzz\"/></tr></table>;\n",
        );
        assert_eq!(count_key(&broken_reference, "javascript:S5260"), 1);

        let valid_references =
            jsx_keys("const el = <table><tr><th id=\"a\"/><td headers=\"a\"/></tr></table>;\n");
        assert_eq!(count_key(&valid_references, "javascript:S5260"), 0);
    }

    #[test]
    fn object_elements_need_text_alternatives() {
        let bare = jsx_keys("const el = <object data=\"x.swf\"/>;\n");
        assert_eq!(count_key(&bare, "javascript:S5264"), 1);

        let text_child = jsx_keys("const el = <object data=\"x.swf\">fallback</object>\n;\n");
        assert_eq!(count_key(&text_child, "javascript:S5264"), 0);

        let labeled = jsx_keys("const el = <object data=\"x.swf\" aria-label=\"movie\"/>\n;\n");
        assert_eq!(count_key(&labeled, "javascript:S5264"), 0);
    }

    #[test]
    fn accesskeys_are_flagged_everywhere() {
        let flagged = jsx_keys("const el = <div accesskey=\"s\"/>;\n");
        assert_eq!(count_key(&flagged, "javascript:S6846"), 1);

        let clean = jsx_keys("const el = <div/>;\n");
        assert_eq!(count_key(&clean, "javascript:S6846"), 0);
    }

    #[test]
    fn tab_indices_are_limited_to_zero_and_minus_one() {
        let positive = jsx_keys("const el = <div tabIndex={3}/>\n;\n");
        assert_eq!(count_key(&positive, "javascript:S6841"), 1);

        let removable = jsx_keys("const el = <div tabIndex={-1}/>\n;\n");
        assert_eq!(count_key(&removable, "javascript:S6841"), 0);

        let string_value = jsx_keys("const el = <div tabIndex=\"2\"/>\n;\n");
        assert_eq!(count_key(&string_value, "javascript:S6841"), 1);

        let dynamic = jsx_keys("let t = 0;\nconst el = <div tabIndex={t}/>\n;\n");
        assert_eq!(count_key(&dynamic, "javascript:S6841"), 0);
    }

    #[test]
    fn headings_need_text_content_or_labels() {
        let bare = jsx_keys("const el = <h1/>;\n");
        assert_eq!(count_key(&bare, "javascript:S6850"), 1);

        let textual = jsx_keys("const el = <h2>Quarterly results</h2>;\n");
        assert_eq!(count_key(&textual, "javascript:S6850"), 0);

        let aria_labeled = jsx_keys("const el = <h3 aria-label=\"Summary\"/>;\n");
        assert_eq!(count_key(&aria_labeled, "javascript:S6850"), 0);

        let titled = jsx_keys("const el = <h4 title=\"Status\"/>;\n");
        assert_eq!(count_key(&titled, "javascript:S6850"), 0);

        let nested_text = jsx_keys("const el = <h5><span>Total</span></h5>;\n");
        assert_eq!(count_key(&nested_text, "javascript:S6850"), 0);

        let not_heading = jsx_keys("const el = <p>text</p>;\n");
        assert_eq!(count_key(&not_heading, "javascript:S6850"), 0);
    }

    #[test]
    fn redundant_alt_texts_are_flagged() {
        let filler_word = jsx_keys("const el = <img src=\"report.pdf\" alt=\"Image\"/>;\n");
        assert_eq!(count_key(&filler_word, "javascript:S6851"), 1);

        let file_name = jsx_keys("const el = <img src=\"chart.png\" alt=\"Chart\"/>;\n");
        assert_eq!(count_key(&file_name, "javascript:S6851"), 1);

        let trimmed_and_cased = jsx_keys("const el = <img src=\"LOGO.png\" alt=\"  Logo \"/>;\n");
        assert_eq!(count_key(&trimmed_and_cased, "javascript:S6851"), 1);

        let descriptive =
            jsx_keys("const el = <img src=\"chart.png\" alt=\"Sales by region\"/>;\n");
        assert_eq!(count_key(&descriptive, "javascript:S6851"), 0);

        let different_stem = jsx_keys("const el = <img src=\"team.jpg\" alt=\"Office\"/>;\n");
        assert_eq!(count_key(&different_stem, "javascript:S6851"), 0);
    }

    #[test]
    fn anchors_need_href_or_accessible_text() {
        let bare_anchor = jsx_keys("const el = <a/>;\n");
        assert_eq!(count_key(&bare_anchor, "javascript:S6827"), 1);

        let linked = jsx_keys("const el = <a href=\"/docs\"/>;\n");
        assert_eq!(count_key(&linked, "javascript:S6827"), 0);

        let unlabeled_named = jsx_keys("const el = <a aria-label=\"Open docs\"/>;\n");
        assert_eq!(count_key(&unlabeled_named, "javascript:S6827"), 1);

        let textual = jsx_keys("const el = <a>Documentation</a>;\n");
        assert_eq!(count_key(&textual, "javascript:S6827"), 0);

        let other_tag = jsx_keys("const el = <span/>;\n");
        assert_eq!(count_key(&other_tag, "javascript:S6827"), 0);
    }

    #[test]
    fn duplicate_implicit_roles_are_flagged() {
        let list_role = jsx_keys("const el = <ul role=\"list\"><li>Item</li></ul>;\n");
        assert_eq!(count_key(&list_role, "javascript:S6822"), 1);
        assert_eq!(count_key(&list_role, "javascript:S6819"), 1);

        let nav_role = jsx_keys("const el = <nav role=\"navigation\"/>;\n");
        assert_eq!(count_key(&nav_role, "javascript:S6822"), 1);
        assert_eq!(count_key(&nav_role, "javascript:S6819"), 1);

        let changed_role = jsx_keys("const el = <ul role=\"toolbar\"><li>Item</li></ul>;\n");
        assert_eq!(count_key(&changed_role, "javascript:S6822"), 0);
        assert_eq!(count_key(&changed_role, "javascript:S6819"), 0);

        let plain_list = jsx_keys("const el = <ul><li>Item</li></ul>;\n");
        assert_eq!(count_key(&plain_list, "javascript:S6822"), 0);
        assert_eq!(count_key(&plain_list, "javascript:S6819"), 0);
    }

    #[test]
    fn abstract_roles_are_flagged() {
        let select_role = jsx_keys("const el = <div role=\"select\"/>;\n");
        assert_eq!(count_key(&select_role, "javascript:S6821"), 1);

        let composite_role = jsx_keys("const el = <div role=\"composite\"/>;\n");
        assert_eq!(count_key(&composite_role, "javascript:S6821"), 1);

        let concrete_role = jsx_keys("const el = <div role=\"note\"/>;\n");
        assert_eq!(count_key(&concrete_role, "javascript:S6821"), 0);
    }

    #[test]
    fn aria_values_are_validated_against_tables() {
        let bad_boolean = jsx_keys("const el = <div aria-hidden=\"yes\"/>;\n");
        assert_eq!(count_key(&bad_boolean, "javascript:S6793"), 1);

        let good_boolean = jsx_keys("const el = <div aria-hidden=\"true\"/>;\n");
        assert_eq!(count_key(&good_boolean, "javascript:S6793"), 0);

        let bad_token = jsx_keys("const el = <div aria-live=\"fast\"/>;\n");
        assert_eq!(count_key(&bad_token, "javascript:S6793"), 1);

        let good_token = jsx_keys("const el = <div aria-live=\"polite\"/>;\n");
        assert_eq!(count_key(&good_token, "javascript:S6793"), 0);

        let bad_numeric = jsx_keys("const el = <div aria-level=\"two\"/>;\n");
        assert_eq!(count_key(&bad_numeric, "javascript:S6793"), 1);

        let good_numeric = jsx_keys("const el = <div aria-level=\"2\"/>;\n");
        assert_eq!(count_key(&good_numeric, "javascript:S6793"), 0);

        let dynamic_value = jsx_keys("let mode = 'polite';\nconst el = <div aria-live={mode}/>;\n");
        assert_eq!(count_key(&dynamic_value, "javascript:S6793"), 0);
    }

    #[test]
    fn list_roles_require_owned_listitems() {
        let bare = jsx_keys("const el = <div role=\"list\"/>;\n");
        assert_eq!(count_key(&bare, "javascript:S6807"), 1);

        let implicit_owned = jsx_keys("const el = <div role=\"list\"><li>Item</li></div>;\n");
        assert_eq!(count_key(&implicit_owned, "javascript:S6807"), 0);

        let explicit_owned =
            jsx_keys("const el = <div role=\"list\"><div role=\"listitem\">Item</div></div>;\n");
        assert_eq!(count_key(&explicit_owned, "javascript:S6807"), 0);
    }

    #[test]
    fn unsupported_aria_properties_are_flagged_per_role() {
        let unsupported = jsx_keys("const el = <div role=\"heading\" aria-selected=\"true\"/>;\n");
        assert_eq!(count_key(&unsupported, "javascript:S6811"), 1);

        let supported = jsx_keys("const el = <div role=\"heading\" aria-level=\"2\"/>;\n");
        assert_eq!(count_key(&supported, "javascript:S6811"), 0);

        let global_property =
            jsx_keys("const el = <div role=\"heading\" aria-hidden=\"true\"/>;\n");
        assert_eq!(count_key(&global_property, "javascript:S6811"), 0);
    }

    #[test]
    fn activedescendant_requires_tab_index() {
        let missing = jsx_keys("const el = <div aria-activedescendant=\"opt-1\"/>;\n");
        assert_eq!(count_key(&missing, "javascript:S6823"), 1);

        let camel_case =
            jsx_keys("const el = <div aria-activedescendant=\"opt-1\" tabIndex={0}/>;\n");
        assert_eq!(count_key(&camel_case, "javascript:S6823"), 0);

        let lower_case =
            jsx_keys("const el = <div aria-activedescendant=\"opt-1\" tabindex=\"0\"/>;\n");
        assert_eq!(count_key(&lower_case, "javascript:S6823"), 0);

        let spread_props =
            jsx_keys("const el = <div {...rest} aria-activedescendant=\"opt-1\"/>;\n");
        assert_eq!(count_key(&spread_props, "javascript:S6823"), 0);
    }

    #[test]
    fn roles_must_be_allowed_on_their_elements() {
        let heading_role = jsx_keys("const el = <h1 role=\"button\">Title</h1>;\n");
        assert_eq!(count_key(&heading_role, "javascript:S6824"), 1);

        let cell_role = jsx_keys("const el = <td role=\"link\">x</td>;\n");
        assert_eq!(count_key(&cell_role, "javascript:S6824"), 1);

        let allowed_cell = jsx_keys("const el = <td role=\"cell\">x</td>;\n");
        assert_eq!(count_key(&allowed_cell, "javascript:S6824"), 0);

        let unrestricted_tag = jsx_keys("const el = <div role=\"button\"/>;\n");
        assert_eq!(count_key(&unrestricted_tag, "javascript:S6824"), 0);

        let list_toolbar = jsx_keys("const el = <ul role=\"toolbar\"><li>x</li></ul>;\n");
        assert_eq!(count_key(&list_toolbar, "javascript:S6824"), 0);
    }

    #[test]
    fn aria_hidden_must_not_hide_focusable_elements() {
        let hidden_button = jsx_keys("const el = <button aria-hidden=\"true\">Go</button>;\n");
        assert_eq!(count_key(&hidden_button, "javascript:S6825"), 1);

        let hidden_tabbable = jsx_keys("const el = <div aria-hidden=\"true\" tabIndex={0}/>;\n");
        assert_eq!(count_key(&hidden_tabbable, "javascript:S6825"), 1);

        let hidden_static = jsx_keys("const el = <div aria-hidden=\"true\">text</div>;\n");
        assert_eq!(count_key(&hidden_static, "javascript:S6825"), 0);

        let negative_index = jsx_keys("const el = <div aria-hidden=\"true\" tabIndex={-1}/>;\n");
        assert_eq!(count_key(&negative_index, "javascript:S6825"), 0);

        let visible_button = jsx_keys("const el = <button>Go</button>;\n");
        assert_eq!(count_key(&visible_button, "javascript:S6825"), 0);
    }

    #[test]
    fn autocomplete_values_must_match_input_types() {
        let mismatched_scope =
            jsx_keys("const el = <input type=\"text\" autoComplete=\"email\"/>;\n");
        assert_eq!(count_key(&mismatched_scope, "javascript:S6840"), 1);

        let unknown_token =
            jsx_keys("const el = <input type=\"text\" autoComplete=\"banana\"/>;\n");
        assert_eq!(count_key(&unknown_token, "javascript:S6840"), 1);

        let matching_scope =
            jsx_keys("const el = <input type=\"email\" autoComplete=\"email\"/>;\n");
        assert_eq!(count_key(&matching_scope, "javascript:S6840"), 0);

        let general_token = jsx_keys("const el = <input autoComplete=\"on\"/>;\n");
        assert_eq!(count_key(&general_token, "javascript:S6840"), 0);

        let select_field = jsx_keys("const el = <select autoComplete=\"postal-code\"/>;\n");
        assert_eq!(count_key(&select_field, "javascript:S6840"), 0);

        let textarea_field = jsx_keys("const el = <textarea autoComplete=\"street-address\"/>;\n");
        assert_eq!(count_key(&textarea_field, "javascript:S6840"), 0);

        let other_tag = jsx_keys("const el = <div autoComplete=\"banana\"/>;\n");
        assert_eq!(count_key(&other_tag, "javascript:S6840"), 0);
    }

    #[test]
    fn noninteractive_elements_reject_interactive_roles() {
        let div_button = jsx_keys("const el = <div role=\"button\" tabIndex={0}>OK</div>;\n");
        assert_eq!(count_key(&div_button, "javascript:S6842"), 1);

        let span_link = jsx_keys("const el = <span role=\"link\">x</span>;\n");
        assert_eq!(count_key(&span_link, "javascript:S6842"), 1);

        let native_button = jsx_keys("const el = <button>OK</button>;\n");
        assert_eq!(count_key(&native_button, "javascript:S6842"), 0);

        let structural_div = jsx_keys("const el = <div role=\"note\">x</div>;\n");
        assert_eq!(count_key(&structural_div, "javascript:S6842"), 0);
    }

    #[test]
    fn interactive_elements_reject_structural_roles() {
        let button_list = jsx_keys("const el = <button role=\"list\">x</button>;\n");
        assert_eq!(count_key(&button_list, "javascript:S6843"), 1);

        let link_article = jsx_keys("const el = <a href=\"/docs\" role=\"article\">x</a>;\n");
        assert_eq!(count_key(&link_article, "javascript:S6843"), 1);

        let matching_button = jsx_keys("const el = <button role=\"checkbox\"/>;\n");
        assert_eq!(count_key(&matching_button, "javascript:S6843"), 0);

        let plain_button = jsx_keys("const el = <button/>;\n");
        assert_eq!(count_key(&plain_button, "javascript:S6843"), 0);
    }

    #[test]
    fn interactive_roles_require_focusable_elements() {
        let unfocusable = jsx_keys("const el = <div role=\"button\"/>;\n");
        assert_eq!(count_key(&unfocusable, "javascript:S6852"), 1);

        let tabbable = jsx_keys("const el = <div role=\"button\" tabIndex={0}/>;\n");
        assert_eq!(count_key(&tabbable, "javascript:S6852"), 0);

        let negative_index = jsx_keys("const el = <div role=\"button\" tabIndex={-1}/>;\n");
        assert_eq!(count_key(&negative_index, "javascript:S6852"), 0);

        let native_control = jsx_keys("const el = <button/>;\n");
        assert_eq!(count_key(&native_control, "javascript:S6852"), 0);

        let anchor = jsx_keys("const el = <a href=\"/docs\">docs</a>;\n");
        assert_eq!(count_key(&anchor, "javascript:S6852"), 0);
    }

    #[test]
    fn anchor_clicks_require_href_or_buttons() {
        let click_only = jsx_keys("const el = <a onClick={openMenu}>Menu</a>;\n");
        assert_eq!(count_key(&click_only, "javascript:S6844"), 1);

        let with_href = jsx_keys("const el = <a href=\"/menu\" onClick={openMenu}>Menu</a>;\n");
        assert_eq!(count_key(&with_href, "javascript:S6844"), 0);

        let plain_anchor = jsx_keys("const el = <a href=\"/docs\">docs</a>;\n");
        assert_eq!(count_key(&plain_anchor, "javascript:S6844"), 0);

        let button_click = jsx_keys("const el = <button onClick={openMenu}>Menu</button>;\n");
        assert_eq!(count_key(&button_click, "javascript:S6844"), 0);
    }

    #[test]
    fn positive_tab_indices_need_interactive_elements() {
        let static_div = jsx_keys("const el = <div tabIndex={0}/>;\n");
        assert_eq!(count_key(&static_div, "javascript:S6845"), 1);

        let interactive_button = jsx_keys("const el = <button tabIndex={0}/>;\n");
        assert_eq!(count_key(&interactive_button, "javascript:S6845"), 0);

        let programmatic = jsx_keys("const el = <div tabIndex={-1}/>;\n");
        assert_eq!(count_key(&programmatic, "javascript:S6845"), 0);

        let interactive_role = jsx_keys("const el = <div role=\"button\" tabIndex={0}/>;\n");
        assert_eq!(count_key(&interactive_role, "javascript:S6845"), 0);

        let listbox_container = jsx_keys(
            "const el = <div role=\"listbox\" aria-activedescendant=\"o1\" tabIndex={0}/>;\n",
        );
        assert_eq!(count_key(&listbox_container, "javascript:S6845"), 0);
    }

    #[test]
    fn interaction_handlers_belong_on_interactive_elements() {
        let div_click = jsx_keys("const el = <div onClick={f}/>;\n");
        assert_eq!(count_key(&div_click, "javascript:S6847"), 1);

        let div_change = jsx_keys("const el = <div onChange={f}/>;\n");
        assert_eq!(count_key(&div_change, "javascript:S6847"), 1);

        let two_handlers = jsx_keys("const el = <div onClick={f} onMouseDown={g}/>;\n");
        assert_eq!(count_key(&two_handlers, "javascript:S6847"), 2);

        let button_click = jsx_keys("const el = <button onClick={f}/>;\n");
        assert_eq!(count_key(&button_click, "javascript:S6847"), 0);

        let role_button = jsx_keys("const el = <div role=\"button\" onClick={f}/>;\n");
        assert_eq!(count_key(&role_button, "javascript:S6847"), 0);
    }

    #[test]
    fn click_handlers_need_keyboard_counterparts() {
        let click_only = jsx_keys("const el = <div onClick={f}/>;\n");
        assert_eq!(count_key(&click_only, "javascript:S6848"), 1);

        let with_key = jsx_keys("const el = <div onClick={f} onKeyDown={k}/>;\n");
        assert_eq!(count_key(&with_key, "javascript:S6848"), 0);

        let interactive_button = jsx_keys("const el = <button onClick={f}/>;\n");
        assert_eq!(count_key(&interactive_button, "javascript:S6848"), 0);
    }

    #[test]
    fn labels_need_text_and_control_association() {
        let orphan_label = jsx_keys("const el = <label>Surname</label>;\n");
        assert_eq!(count_key(&orphan_label, "javascript:S6853"), 1);

        let empty_label = jsx_keys("const el = <label htmlFor=\"q\"/>;\n");
        assert_eq!(count_key(&empty_label, "javascript:S6853"), 1);

        let bare_label = jsx_keys("const el = <label/>;\n");
        assert_eq!(count_key(&bare_label, "javascript:S6853"), 1);

        let for_attribute = jsx_keys("const el = <label htmlFor=\"q\">Query</label>;\n");
        assert_eq!(count_key(&for_attribute, "javascript:S6853"), 0);

        let nested_control = jsx_keys("const el = <label>Name<input/></label>;\n");
        assert_eq!(count_key(&nested_control, "javascript:S6853"), 0);
    }
}
