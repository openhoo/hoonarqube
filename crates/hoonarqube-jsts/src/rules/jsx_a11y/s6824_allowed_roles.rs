use super::walker::{
    A11yCollector, explicit_role, jsx_element_tag, jsx_has_spread_attribute, jsx_tag_is_intrinsic,
};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
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
}

/// Roles each restrictive element permits (`S6824`); elements outside this
/// table accept any explicit role.
const ALLOWED_ROLES_BY_ELEMENT: &[(&str, &[&str])] = &[
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
const LIST_CONTAINER_ROLES: [&str; 9] = [
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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6824_flags_disallowed_roles_on_restrictive_elements() {
        let nav_banner = jsx_keys("const el = <nav role=\"banner\"/>;\n");
        assert_eq!(count_key(&nav_banner, "javascript:S6824"), 1);

        let li_gridcell = jsx_keys("const el = <li role=\"gridcell\">x</li>;\n");
        assert_eq!(count_key(&li_gridcell, "javascript:S6824"), 1);
    }

    #[test]
    fn s6824_accepts_listed_roles_and_unrestricted_elements() {
        let section_status = jsx_keys("const el = <section role=\"status\">x</section>;\n");
        assert_eq!(count_key(&section_status, "javascript:S6824"), 0);

        let row_role = jsx_keys("const el = <tr role=\"row\"/>;\n");
        assert_eq!(count_key(&row_role, "javascript:S6824"), 0);

        let unrestricted = jsx_keys("const el = <div role=\"banner\"/>;\n");
        assert_eq!(count_key(&unrestricted, "javascript:S6824"), 0);
    }

    #[test]
    fn s6824_allows_presentation_on_headings_but_skips_custom_tags() {
        let heading_presentation = jsx_keys("const el = <h2 role=\"presentation\">Title</h2>;\n");
        assert_eq!(count_key(&heading_presentation, "javascript:S6824"), 0);

        let custom = jsx_keys("const el = <Nav role=\"banner\"/>;\n");
        assert_eq!(count_key(&custom, "javascript:S6824"), 0);
    }
}
