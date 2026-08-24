use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4052 — pre-generic collection bases lose type safety.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter(|type_node| !is_error_tainted(*type_node))
        .filter(|type_node| {
            base_simple_names(*type_node, source)
                .iter()
                .any(|base| OUTDATED_BASE_TYPES.contains(base))
        })
        .map(|type_node| {
            issue(
                language,
                "S4052",
                "Replace this obsolete base type with a generic collection.",
                range_of(type_node),
            )
        })
        .collect()
}

/// Base types from the pre-generic collections era.
const OUTDATED_BASE_TYPES: [&str; 8] = [
    "ArrayList",
    "Hashtable",
    "Queue",
    "Stack",
    "SortedList",
    "CollectionBase",
    "DictionaryBase",
    "ReadOnlyCollectionBase",
];
