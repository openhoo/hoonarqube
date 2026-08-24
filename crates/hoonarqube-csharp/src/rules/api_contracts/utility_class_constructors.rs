use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, modifiers_of, range_of};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1118 — utility classes are reached through their static
/// members, not through instances.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_node) {
            continue;
        }
        let methods = member_declarations_of_kind(class_node, "method_declaration");
        if methods.is_empty()
            || !methods
                .iter()
                .all(|method| has_modifier(&modifiers_of(*method, source), "static"))
        {
            continue;
        }
        let fields_hold_state = type_members(class_node)
            .into_iter()
            .filter(|member| matches!(member.kind(), "field_declaration"))
            .any(|field| {
                let modifiers = modifiers_of(field, source);
                !has_modifier(&modifiers, "static") && !has_modifier(&modifiers, "const")
            });
        if fields_hold_state {
            continue;
        }
        for constructor in member_declarations_of_kind(class_node, "constructor_declaration") {
            let modifiers = modifiers_of(constructor, source);
            if has_modifier(&modifiers, "public") || has_modifier(&modifiers, "internal") {
                issues.push(issue(
                    language,
                    "S1118",
                    "Hide this constructor or declare the class 'static'.",
                    range_of(constructor),
                ));
            }
        }
    }
    issues
}
