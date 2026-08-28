use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, range_of,
};
use crate::rules::modifiers::has_modifier;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration", "struct_declaration"])
        .into_iter()
        .filter(|declaration| !is_error_tainted(*declaration))
        .filter(|declaration| has_modifier(&modifiers_of(*declaration, source), "public"))
        .filter(|declaration| {
            base_simple_names(*declaration, source)
                .iter()
                .any(|base| NON_GENERIC_COLLECTION_BASES.contains(base))
        })
        .map(|declaration| {
            issue(
                language,
                "S3909",
                "Refactor this collection to implement 'System.Collections.ObjectModel.Collection<T>'.",
                range_of(name_anchor(declaration), source),
            )
        })
        .collect()
}

/// Public collections should expose the generic collection contract.
const NON_GENERIC_COLLECTION_BASES: [&str; 5] = [
    "CollectionBase",
    "IEnumerable",
    "ICollection",
    "IList",
    "IDictionary",
];
