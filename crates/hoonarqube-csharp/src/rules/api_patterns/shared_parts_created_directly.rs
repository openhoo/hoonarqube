use super::support::attribute_argument_texts;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::modifiers::has_any_attribute;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4277 — MEF parts marked shared must be resolved through
/// the container; `new` bypasses the sharing scope and creates a second
/// instance. Bound: same-file parts and creations.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let shared_names: std::collections::HashSet<&str> =
        collect_kinds(root, &TYPE_DECLARATION_KINDS)
            .into_iter()
            .filter(|type_node| is_shared_mef_part(*type_node, source))
            .filter_map(|type_node| type_node.child_by_field_name("name"))
            .map(|name| node_text(name, source))
            .collect();
    if shared_names.is_empty() {
        return Vec::new();
    }
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            creation
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    shared_names.contains(simple_name(node_text(type_node, source)))
                })
        })
        .map(|creation| {
            issue(
                language,
                "S4277",
                "Resolve this shared MEF part through the container instead of 'new'.",
                range_of(creation),
            )
        })
        .collect()
}

/// Whether the type carries `[Shared]` or a shared `PartCreationPolicy`.
fn is_shared_mef_part(type_node: Node<'_>, source: &str) -> bool {
    has_any_attribute(type_node, source, &["Shared"])
        || collect_kinds(type_node, &["attribute"])
            .iter()
            .any(|attribute| {
                attribute_argument_texts(*attribute, source)
                    .iter()
                    .any(|text| text.ends_with("CreationPolicy.Shared") || *text == "Shared")
                    && {
                        let name = attribute
                            .children(&mut attribute.walk())
                            .find(tree_sitter::Node::is_named)
                            .map(|name| node_text(name, source).ends_with("PartCreationPolicy"));
                        name == Some(true)
                    }
            })
}
