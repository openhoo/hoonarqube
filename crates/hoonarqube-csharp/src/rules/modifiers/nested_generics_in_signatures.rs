use crate::CsLanguage;
use crate::cst::{ancestors_of, collect_kinds, issue, range_of, signature_regions};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4017 — nested generic types resist inference; signatures
/// should stay shallow.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declaration in collect_kinds(
        root,
        &[
            "method_declaration",
            "delegate_declaration",
            "operator_declaration",
            "indexer_declaration",
        ],
    ) {
        let anchor = signature_regions(declaration)
            .into_iter()
            .find_map(|region| {
                collect_kinds(region, &["generic_name"])
                    .into_iter()
                    .find(|generic| has_nested_generics(*generic))
                    .map(|generic| {
                        ancestors_of(generic)
                            .find(|ancestor| ancestor.kind() == "parameter")
                            .unwrap_or(generic)
                    })
            });
        let Some(anchor) = anchor else {
            continue;
        };
        issues.push(issue(
            language,
            "S4017",
            "Refactor this method to remove the nested type argument.",
            range_of(anchor, source),
        ));
    }
    issues
}

/// True when one generic argument nests another (`List<Dictionary<K, V>>`).
fn has_nested_generics(root: Node<'_>) -> bool {
    fn walk(node: Node<'_>, depth: u32) -> bool {
        let depth = depth + u32::from(node.kind() == "generic_name");
        if depth > 1 {
            return true;
        }
        let mut cursor = node.walk();
        node.children(&mut cursor).any(|child| walk(child, depth))
    }
    walk(root, 0)
}
