use super::support::has_modifier;
use super::support::subtree_contains_kind;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, range_of, signature_regions};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4000 — public signatures must not leak pointer types into
/// managed callers.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for declaration in collect_kinds(
        root,
        &[
            "method_declaration",
            "constructor_declaration",
            "operator_declaration",
            "indexer_declaration",
            "delegate_declaration",
        ],
    ) {
        if !has_modifier(&modifiers_of(declaration, source), "public") {
            continue;
        }
        let leaks_pointer = signature_regions(declaration)
            .iter()
            .any(|region| subtree_contains_kind(*region, "pointer_type"));
        if !leaks_pointer {
            continue;
        }
        let anchor = declaration
            .child_by_field_name("name")
            .unwrap_or(declaration);
        issues.push(issue(
            language,
            "S4000",
            "Do not expose pointer types in public signatures.",
            range_of(anchor, source),
        ));
    }
    issues
}
