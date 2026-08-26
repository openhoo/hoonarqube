use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of, signature_regions};
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
        let nests_generics = signature_regions(declaration)
            .iter()
            .any(|region| has_nested_generics(*region));
        if !nests_generics {
            continue;
        }
        let anchor = declaration
            .child_by_field_name("name")
            .unwrap_or(declaration);
        issues.push(issue(
            language,
            "S4017",
            "Refactor this signature to avoid nested generic types.",
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
