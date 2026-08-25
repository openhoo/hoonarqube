use super::walker::{A11yCollector, explicit_role, jsx_find_attribute};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
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
}

// ===== Batch4 groups A1-A3: JSX accessibility rules =====
//
// Table-driven jsx-a11y checks over one JSX walk: `S1077` (alt text),
// `S1082` (mouse handlers), `S1090` (iframe title), `S4084` (media
// captions), `S5254` (html lang), `S5256`/`S5257`/`S5260` (table
// structure), `S5264` (object alternative), `S6846` (accesskey), and
// `S6841` (tabIndex values). Groups A2/A3 add the role and interaction
// matrices.

/// Abstract roles that must never reach an element's `role` attribute.
const ABSTRACT_ROLES: [&str; 12] = [
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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6821_flags_widget_and_window_roles() {
        let widget = jsx_keys("const el = <nav role=\"widget\"/>;\n");
        assert_eq!(count_key(&widget, "javascript:S6821"), 1);

        let window_role = jsx_keys("const el = <section role=\"window\"/>;\n");
        assert_eq!(count_key(&window_role, "javascript:S6821"), 1);
    }

    #[test]
    fn s6821_accepts_concrete_and_dynamic_roles() {
        let concrete = jsx_keys("const el = <section role=\"region\"/>;\n");
        assert_eq!(count_key(&concrete, "javascript:S6821"), 0);

        let dynamic = jsx_keys("let r = 'widget';\nconst el = <div role={r}/>;\n");
        assert_eq!(count_key(&dynamic, "javascript:S6821"), 0);

        let no_role = jsx_keys("const el = <nav/>;\n");
        assert_eq!(count_key(&no_role, "javascript:S6821"), 0);
    }
}
