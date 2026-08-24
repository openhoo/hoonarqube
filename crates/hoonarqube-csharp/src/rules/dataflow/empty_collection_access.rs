use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::{callee_name, invocation_arguments};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4158 — indexing or iterating an empty collection fails
/// at runtime. Bound: direct chains off a provably empty creation
/// (indexing, `MoveNext`, `foreach`); values stored into variables lose
/// their provenance on purpose.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for creation in collect_kinds(
        root,
        &[
            "array_creation_expression",
            "implicit_array_creation_expression",
            "object_creation_expression",
        ],
    ) {
        if is_error_tainted(creation) || !is_empty_collection_creation(creation, source) {
            continue;
        }
        let mut current = Some(creation);
        while let Some(node) = current {
            current = node.parent();
            match node.parent().map(|parent| parent.kind()) {
                Some("parenthesized_expression") => {}
                Some("element_access_expression" | "foreach_statement") => {
                    issues.push(issue(
                        language,
                        "S4158",
                        "This collection is created empty; accessing its elements will fail at runtime.",
                        range_of(creation),
                    ));
                    break;
                }
                Some("invocation_expression") => {
                    if node
                        .parent()
                        .is_some_and(|parent| callee_name(parent, source) == Some("MoveNext"))
                    {
                        issues.push(issue(
                            language,
                            "S4158",
                            "This collection is created empty; accessing its elements will fail at runtime.",
                            range_of(creation),
                        ));
                        break;
                    }
                    break;
                }
                _ => break,
            }
        }
    }
    issues
}

/// Collection types a zero-argument construction yields empty.
const EMPTY_ACCESS_COLLECTION_TYPES: [&str; 9] = [
    "List",
    "Dictionary",
    "HashSet",
    "SortedSet",
    "SortedList",
    "SortedDictionary",
    "Queue",
    "Stack",
    "LinkedList",
];

/// Whether this creation provably produces an empty collection:
/// a zero-length array, an empty `{}` initializer, or a known
/// collection type constructed without arguments.
fn is_empty_collection_creation(node: Node<'_>, source: &str) -> bool {
    match node.kind() {
        "array_creation_expression" => {
            let ranks = collect_kinds(node, &["array_rank_specifier"]);
            !ranks.is_empty()
                && ranks.iter().all(|rank| {
                    let sizes = collect_kinds(*rank, &["integer_literal"]);
                    sizes.is_empty() || sizes.iter().all(|size| node_text(*size, source) == "0")
                })
        }
        "implicit_array_creation_expression" => {
            let initializer = collect_kinds(node, &["initializer_expression"]);
            initializer.iter().all(|init| {
                !init
                    .children(&mut init.walk())
                    .any(|child| child.is_named())
            })
        }
        "object_creation_expression" => {
            let type_name = node
                .child_by_field_name("type")
                .map_or("", |type_node| simple_name(node_text(type_node, source)));
            EMPTY_ACCESS_COLLECTION_TYPES.contains(&type_name)
                && invocation_arguments(node).is_empty()
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    const KEY: &str = "csharpsquid:S4158";

    #[test]
    fn s4158_minimal_empty_body_is_clean() {
        let report = analyze_default("class C {\n    void M() {\n    }\n}\n");
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s4158_indexing_empty_array_flags() {
        let report = analyze_default(
            "class C {\n    void M() {\n        var first = new int[0][0];\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].range.start.line, 3);
    }

    #[test]
    fn s4158_foreach_over_empty_list_flags() {
        let report = analyze_default(
            "class C {\n    void M() {\n        foreach (var item in new List<int>()) {\n            Keep(item);\n        }\n    }\n}\n",
        );
        let found = with_key(&report, KEY);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn s4158_parenthesized_chain_still_flags() {
        let report = analyze_default(
            "class C {\n    void M() {\n        var head = (new Dictionary<string, int>())[\"k\"];\n    }\n}\n",
        );
        assert_eq!(with_key(&report, KEY).len(), 1);
    }

    #[test]
    fn s4158_non_empty_creation_is_clean() {
        let report = analyze_default(
            "class C {\n    void M() {\n        var first = new[] { 1 }[0];\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s4158_stored_value_loses_provenance_on_purpose() {
        let report = analyze_default(
            "class C {\n    void M() {\n        var empty = new List<int>();\n        Log(empty.Count);\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }

    #[test]
    fn s4158_unknown_type_construction_is_ignored() {
        let report = analyze_default(
            "class C {\n    void M() {\n        var first = new Weird()[0];\n    }\n}\n",
        );
        assert!(with_key(&report, KEY).is_empty());
    }
}
