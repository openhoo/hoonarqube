use super::walker::{A11yCollector, SubtreeFacts, explicit_role, jsx_find_attribute};
use crate::support::RuleScope;
use oxc_ast::ast::JSXElement;
use oxc_ast_visit::Visit;
use oxc_span::GetSpan;

impl A11yCollector<'_> {
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
}

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

#[cfg(test)]
mod tests {
    use crate::test_support::*;

    #[test]
    fn s6807_flags_treeless_trees_and_tabless_tablists() {
        let tree = jsx_keys("const el = <ul role=\"tree\"/>;\n");
        assert_eq!(count_key(&tree, "javascript:S6807"), 1);

        let tablist = jsx_keys("const el = <div role=\"tablist\"/>;\n");
        assert_eq!(count_key(&tablist, "javascript:S6807"), 1);
    }

    #[test]
    fn s6807_accepts_menus_with_owned_menuitems() {
        let menu =
            jsx_keys("const el = <div role=\"menu\"><div role=\"menuitem\">Open</div></div>;\n");
        assert_eq!(count_key(&menu, "javascript:S6807"), 0);

        let implicit_listitem = jsx_keys("const el = <div role=\"list\"><li>Item</li></div>;\n");
        assert_eq!(count_key(&implicit_listitem, "javascript:S6807"), 0);
    }

    #[test]
    fn s6807_ignores_roles_without_required_children() {
        let note = jsx_keys("const el = <div role=\"note\">text</div>;\n");
        assert_eq!(count_key(&note, "javascript:S6807"), 0);
    }
}
