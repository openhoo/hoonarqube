// Residual rule machinery for 'jsx_a11y' (extracted from lib.rs).
use crate::rules::jsx_a11y::walker::jsx_attribute_name;
use oxc_ast::ast::{JSXAttributeItem, JSXOpeningElement};

/// Tag to implicit ARIA role, refined by the `a[href]` and `input[type]`
/// adjustments in [`implicit_role`].
pub(crate) const IMPLICIT_ROLES: [(&str, &str); 22] = [
    ("article", "article"),
    ("aside", "complementary"),
    ("button", "button"),
    ("footer", "contentinfo"),
    ("form", "form"),
    ("h1", "heading"),
    ("h2", "heading"),
    ("h3", "heading"),
    ("h4", "heading"),
    ("h5", "heading"),
    ("h6", "heading"),
    ("header", "banner"),
    ("img", "img"),
    ("li", "listitem"),
    ("main", "main"),
    ("nav", "navigation"),
    ("ol", "list"),
    ("section", "region"),
    ("table", "table"),
    ("tbody", "rowgroup"),
    ("ul", "list"),
    ("textarea", "textbox"),
];

/// Roles that make an element interactive (matrix groups `S6842`, `S6843`,
/// `S6845`, and `S6852`).
pub(crate) const INTERACTIVE_ROLES: [&str; 29] = [
    "button",
    "checkbox",
    "columnheader",
    "combobox",
    "grid",
    "gridcell",
    "link",
    "listbox",
    "menu",
    "menubar",
    "menuitem",
    "menuitemcheckbox",
    "menuitemradio",
    "option",
    "progressbar",
    "radio",
    "radiogroup",
    "row",
    "rowheader",
    "scrollbar",
    "searchbox",
    "slider",
    "spinbutton",
    "switch",
    "tab",
    "textbox",
    "tree",
    "treegrid",
    "treeitem",
];

/// Roles that never make an element interactive (`S6843`); interactive
/// elements must not take them.
pub(crate) const NON_INTERACTIVE_ROLES: [&str; 28] = [
    "alert",
    "article",
    "banner",
    "complementary",
    "contentinfo",
    "definition",
    "document",
    "feed",
    "figure",
    "form",
    "img",
    "list",
    "listitem",
    "log",
    "main",
    "math",
    "navigation",
    "none",
    "note",
    "presentation",
    "region",
    "rowgroup",
    "search",
    "status",
    "table",
    "term",
    "time",
    "tooltip",
];

/// Whether the opening tag carries the named attribute at all.
pub(crate) fn jsx_has_attribute(opening: &JSXOpeningElement<'_>, name: &str) -> bool {
    opening.attributes.iter().any(|item| {
        matches!(item, JSXAttributeItem::Attribute(attribute) if jsx_attribute_name(attribute) == Some(name))
    })
}

/// Whether a language tag looks like a BCP-47 subset form (`en`, `pt-BR`).
pub(crate) fn language_tag_is_valid(value: &str) -> bool {
    let segments: Vec<&str> = value.split('-').collect();
    if segments.len() > 3 {
        return false;
    }
    let Some((primary, subtags)) = segments.split_first() else {
        return false;
    };
    (2..=3).contains(&primary.len())
        && primary.chars().all(|ch| ch.is_ascii_alphabetic())
        && subtags.iter().all(|segment| {
            !segment.is_empty()
                && segment.len() <= 8
                && segment.chars().all(|ch| ch.is_ascii_alphanumeric())
        })
}
