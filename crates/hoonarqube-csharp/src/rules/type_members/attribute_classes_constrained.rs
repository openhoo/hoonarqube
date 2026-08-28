use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, issue, node_text, range_of};
use crate::rules::modifiers::has_any_attribute;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3993 — attribute classes should declare `[AttributeUsage]`
/// so compilers and tooling know where they apply.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| base_simple_names(*class_node, source).contains(&"Attribute"))
        .filter(|class_node| {
            !has_any_attribute(
                *class_node,
                source,
                &["AttributeUsage", "AttributeUsageAttribute"],
            )
        })
        .filter_map(|class_node| class_node.child_by_field_name("name"))
        .map(|name| {
            issue(
                language,
                "S3993",
                format!("Specify AttributeUsage on '{}'.", node_text(name, source)),
                range_of(name, source),
            )
        })
        .collect()
}
