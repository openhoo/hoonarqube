use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of, simple_name,
};
use crate::rules::modifiers::has_modifier;
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
                .is_some_and(|type_node| is_mutable_collection(type_node, source))
        })
        .filter_map(|property| {
            accessors_of(property)
                .into_iter()
                .find(|accessor| {
                    let modifiers = modifiers_of(*accessor, source);
                    let private_only = has_modifier(&modifiers, "private")
                        && !has_modifier(&modifiers, "protected");
                    accessor_keyword(*accessor, source) == "set" && !private_only
                })
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

fn is_mutable_collection(type_node: Node<'_>, source: &str) -> bool {
    type_node.kind() == "array_type"
        || MUTABLE_COLLECTION_TYPES.contains(&simple_name(node_text(type_node, source)))
}

/// Mutable collection types whose properties should not carry exposed
/// setters. Exact simple-name matching avoids substring hits such as
/// `AllowList<T>`.
const MUTABLE_COLLECTION_TYPES: [&str; 14] = [
    "ICollection",
    "IList",
    "IDictionary",
    "List",
    "Dictionary",
    "HashSet",
    "SortedSet",
    "SortedList",
    "SortedDictionary",
    "Queue",
    "Stack",
    "LinkedList",
    "Collection",
    "ObservableCollection",
];

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4004_spares_private_setters_and_similarly_named_types() {
        let report = analyze_default(
            "class A\n{\n    public List<int> Items { get; private set; }\n    public AllowList<int> Rules { get; set; }\n    public DictionaryView<int> View { get; set; }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4004").is_empty());
    }

    #[test]
    fn s4004_flags_arrays_and_interface_typed_collections() {
        let report = analyze_default(
            "class A\n{\n    public int[] Values { get; set; }\n    public System.Collections.Generic.IList<int> Rows { get; protected set; }\n    public ICollection<int> Shared { get; private protected set; }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S4004").len(), 3);
    }
}
