use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::structure::{accessor_keyword, accessors_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4004 — callers mutate collections through the property's
/// value, so setters only invite replacement.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["property_declaration"])
        .into_iter()
        .filter(|property| !is_error_tainted(*property))
        .filter(|property| {
            property
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    COLLECTION_TYPE_MARKERS
                        .iter()
                        .any(|marker| node_text(type_node, source).contains(marker))
                })
        })
        .filter_map(|property| {
            accessors_of(property)
                .into_iter()
                .find(|accessor| accessor_keyword(*accessor, source) == "set")
                .map(|setter| (property, setter))
        })
        .map(|(property, _setter)| {
            let name = property
                .child_by_field_name("name");
            let name_text = name.map_or("property", |name| node_text(name, source));
            issue(
                language,
                "S4004",
                format!(
                    "Make the '{name_text}' property read-only by removing the property setter or making it private."
                ),
                range_of(name.unwrap_or(property), source),
            )
        })
        .collect()
}

/// Collection spellings whose properties should not carry setters.
const COLLECTION_TYPE_MARKERS: [&str; 4] = ["List<", "Dictionary<", "Collection<", "[]"];
