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
