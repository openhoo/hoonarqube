use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, issue, modifiers_of, node_text, range_of};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::modifiers::accessibility_rank;
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
            || accessibility_rank(&modifiers) < 4
        {
            continue;
        }
        let equals_is_open = member_declarations_of_kind(class_node, "method_declaration")
            .into_iter()
            .filter(|method| {
                method
                    .child_by_field_name("name")
                    .is_some_and(|name| node_text(name, source) == "Equals")
            })
            .any(|method| {
                let method_modifiers = modifiers_of(method, source);
                has_modifier(&method_modifiers, "virtual")
                    || has_modifier(&method_modifiers, "abstract")
            });
        if equals_is_open {
            continue;
        }
        let Some(name) = class_node.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S4035",
            format!(
                "Seal class '{}' or implement 'IEqualityComparer<T>' instead.",
                node_text(name, source)
            ),
            range_of(name, source),
        ));
    }
    issues
}
