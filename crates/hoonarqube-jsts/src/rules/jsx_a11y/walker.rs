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
