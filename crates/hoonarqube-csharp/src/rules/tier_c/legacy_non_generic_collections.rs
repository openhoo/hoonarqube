use crate::CsLanguage;
use crate::cst::{is_error_tainted, issue, node_text, range_of};
use crate::rules::security::identifier_usages;
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    identifier_usages(root, source, &LEGACY_COLLECTION_TYPES)
        .into_iter()
        .filter(|identifier| !is_error_tainted(*identifier))
        .filter(|identifier| {
            identifier
                .parent()
                .is_some_and(|parent| parent.kind() != "generic_name")
        })
        .map(|identifier| {
            issue(
                language,
                "S3909",
                format!(
                    "Replace the legacy non-generic collection '{}' with its generic equivalent.",
                    node_text(identifier, source)
                ),
                range_of(identifier),
            )
        })
        .collect()
}

/// csharpsquid:S3909 — legacy non-generic collections (`ArrayList`,
/// `Hashtable`, non-generic `Queue`/`Stack`/`SortedList`). Generic uses such
/// as `Queue<int>` are excluded by their `generic_name` parent.
const LEGACY_COLLECTION_TYPES: [&str; 5] =
    ["ArrayList", "Hashtable", "Queue", "Stack", "SortedList"];
