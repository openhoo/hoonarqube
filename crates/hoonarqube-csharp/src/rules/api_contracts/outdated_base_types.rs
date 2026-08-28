use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, range_of,
};
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4052 — pre-generic collection bases lose type safety.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter(|type_node| !is_error_tainted(*type_node))
        .filter(|type_node| has_modifier(&modifiers_of(*type_node, source), "public"))
        .filter(|type_node| {
            base_simple_names(*type_node, source)
                .iter()
                .any(|base| OUTDATED_BASE_TYPES.contains(base))
        })
        .filter_map(|type_node| {
            let base = base_simple_names(type_node, source)
                .into_iter()
                .find(|base| OUTDATED_BASE_TYPES.contains(base))?;
            let name = type_node.child_by_field_name("name")?;
            issue(
                language,
                "S4052",
                format!("Refactor this type not to derive from an outdated type 'System.{base}'."),
                range_of(name, source),
            )
            .into()
        })
        .collect()
}

/// Base types from the pre-generic collections era.
const OUTDATED_BASE_TYPES: [&str; 8] = [
    "ApplicationException",
    "XmlDocument",
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
        let report = analyze_default("public class Ledger : System.ApplicationException\n{\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S4052").len(), 1);
    }

    #[test]
    fn s4052_counts_nested_legacy_types_together() {
        let report = analyze_default(
            "namespace Store\n{\n    class Shelf\n    {\n        class Box : Hashtable { }\n\n        class Crate : ReadOnlyCollectionBase { }\n    }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4052");
        assert!(flagged.is_empty());
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
        let report = analyze_default(
            "class Lower : applicationexception { }\npublic class Mixed : Queue, IComparable { }\n",
        );
        let flagged = with_key(&report, "csharpsquid:S4052");
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].range.start.line, 2);
    }
}
