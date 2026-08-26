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
                range_of(type_node, source),
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

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s4052_flags_qualified_outdated_bases() {
        let report = analyze_default("class Ledger : System.Collections.ArrayList\n{\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S4052").len(), 1);
    }

    #[test]
    fn s4052_counts_nested_legacy_types_together() {
        let report = analyze_default(
            "namespace Store\n{\n    class Shelf\n    {\n        class Box : Hashtable { }\n\n        class Crate : ReadOnlyCollectionBase { }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4052");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 5);
        assert_eq!(flagged[1].range.start.line, 7);
    }

    #[test]
    fn s4052_ignores_member_usage_of_legacy_collections() {
        let report = analyze_default(
            "class LegacyUser\n{\n    private ArrayList bag = new ArrayList();\n\n    Hashtable Lookup() => new Hashtable();\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S4052").is_empty());
    }

    #[test]
    fn s4052_requires_exact_case_sensitive_names() {
        let report =
            analyze_default("class Lower : arraylist { }\nclass Mixed : Queue, IComparable { }\n");
        let flagged = with_key(&report, "csharpsquid:S4052");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 2);
    }
}
