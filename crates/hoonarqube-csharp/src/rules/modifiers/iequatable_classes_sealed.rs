use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, issue, modifiers_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4035 — IEquatable-implementing classes gain nothing from
/// being open for inheritance and should be sealed.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        let implements_equatable = base_simple_names(class_node, source)
            .iter()
            .any(|name| name.starts_with("IEquatable"));
        if !implements_equatable {
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
            "S4035",
            "Mark this class 'sealed'; it implements 'IEquatable'.",
            range_of(name),
        ));
    }
    issues
}
