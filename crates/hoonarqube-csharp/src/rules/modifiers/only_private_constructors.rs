use super::support::accessibility_rank;
use super::support::has_modifier;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, node_text, range_of, simple_name};
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3453 — classes with only inaccessible constructors can never
/// be instantiated. Classes constructed elsewhere in this file, protected-
/// constructor classes awaiting derivation, static classes, and partial
/// classes spanning files stay untouched.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let instantiations = instantiated_type_names(root, source);
    let mut issues = Vec::new();
    for class_node in collect_kinds(root, &["class_declaration"]) {
        let modifiers = modifiers_of(class_node, source);
        if has_modifier(&modifiers, "static") || has_modifier(&modifiers, "partial") {
            continue;
        }
        let constructors: Vec<Node> = type_members(class_node)
            .into_iter()
            .filter(|member| member.kind() == "constructor_declaration")
            .collect();
        if constructors.is_empty()
            || !constructors
                .iter()
                .all(|ctor| accessibility_rank(&modifiers_of(*ctor, source)) <= 2)
        {
            continue;
        }
        let Some(name) = class_node.child_by_field_name("name") else {
            continue;
        };
        if instantiations.contains(simple_name(node_text(name, source))) {
            continue;
        }
        issues.push(issue(
            language,
            "S3453",
            "Make this class 'static' or give it a non-private constructor.",
            range_of(name),
        ));
    }
    issues
}

/// Names of every `new T(...)` construction site in the file.
fn instantiated_type_names(root: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter_map(|creation| creation.child_by_field_name("type"))
        .map(|type_node| simple_name(node_text(type_node, source)).to_string())
        .collect()
}
