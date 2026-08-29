use super::support::attribute_argument_texts;
use crate::CsLanguage;
use crate::cst::{
    collect_kinds, containing_namespace, direct_attributes, is_error_tainted, issue, node_text,
    range_of, simple_name,
};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4277 — MEF parts marked shared must be resolved through
/// the container; `new` bypasses the sharing scope and creates a second
/// instance. Bound: same-file parts and creations.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let known_types: Vec<KnownType<'_>> = collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter_map(|type_node| {
            let name = type_node.child_by_field_name("name")?;
            Some(KnownType {
                name: simple_name(node_text(name, source)),
                namespace: containing_namespace(type_node, source),
                shared: is_shared_mef_part(type_node, source),
            })
        })
        .collect();
    if known_types.iter().all(|known| !known.shared) {
        return Vec::new();
    }
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            creation
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    resolves_to_shared_part(*creation, type_node, source, &known_types)
                })
        })
        .map(|creation| {
            issue(
                language,
                "S4277",
                "Refactor this code so that it doesn't invoke the constructor of this class.",
                range_of(creation, source),
            )
        })
        .collect()
}

struct KnownType<'a> {
    name: &'a str,
    namespace: String,
    shared: bool,
}

fn resolves_to_shared_part(
    creation: Node<'_>,
    type_node: Node<'_>,
    source: &str,
    known_types: &[KnownType<'_>],
) -> bool {
    let written = node_text(type_node, source)
        .replace("global::", "")
        .replace('@', "");
    let simple = simple_name(&written);
    let candidates: Vec<_> = known_types
        .iter()
        .filter(|candidate| candidate.name == simple)
        .collect();
    if written.contains('.') {
        return candidates.iter().any(|candidate| {
            format!("{}.{}", candidate.namespace, candidate.name).trim_start_matches('.') == written
                && candidate.shared
        });
    }
    let namespace = containing_namespace(creation, source);
    let local: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.namespace == namespace)
        .collect();
    if local.len() == 1 {
        return local[0].shared;
    }
    local.is_empty() && candidates.len() == 1 && candidates[0].shared
}

/// Whether the type carries a shared `PartCreationPolicy`.
fn is_shared_mef_part(type_node: Node<'_>, source: &str) -> bool {
    direct_attributes(type_node).iter().any(|attribute| {
        attribute_argument_texts(*attribute, source)
            .iter()
            .any(|text| text.ends_with("CreationPolicy.Shared") || *text == "Shared")
            && {
                attribute.child_by_field_name("name").is_some_and(|name| {
                    let name = simple_name(node_text(name, source));
                    name.strip_suffix("Attribute").unwrap_or(name) == "PartCreationPolicy"
                })
            }
    })
}
