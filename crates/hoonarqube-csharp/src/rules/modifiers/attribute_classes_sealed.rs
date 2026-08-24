use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, issue, modifiers_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4060 — non-abstract attribute classes should be sealed:
/// nothing is meant to derive from them.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        let derives_attribute = base_simple_names(class_node, source)
            .iter()
            .any(|name| *name == "Attribute" || name.ends_with("Attribute"));
        if !derives_attribute {
            continue;
        }
        let modifiers = modifiers_of(class_node, source);
        if has_modifier(&modifiers, "sealed")
            || has_modifier(&modifiers, "abstract")
            || has_modifier(&modifiers, "static")
        {
            continue;
        }
        let Some(name) = class_node.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S4060",
            "Mark this attribute class 'sealed' or 'abstract'.",
            range_of(name),
        ));
    }
    issues
}
