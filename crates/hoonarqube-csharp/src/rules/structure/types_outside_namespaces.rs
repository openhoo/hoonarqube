use super::support::name_anchor;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::naming::{TYPE_DECLARATION_KINDS, declaration_kind_word};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3903 — types live in named namespaces. A compilation unit
/// holding a single type stays untouched: a lone top-level type is a
/// common, deliberate layout.
pub(crate) fn check(root: Node<'_>, language: CsLanguage) -> Vec<Issue> {
    let file_scope_types: Vec<Node> = collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter(|type_declaration| {
            type_declaration
                .parent()
                .is_some_and(|parent| parent.kind() == "compilation_unit")
        })
        .collect();
    if file_scope_types.len() < 2 {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for type_declaration in file_scope_types {
        if is_error_tainted(type_declaration) {
            continue;
        }
        issues.push(issue(
            language,
            "S3903",
            format!(
                "Move this {} into a namespace.",
                declaration_kind_word(type_declaration.kind())
            ),
            range_of(name_anchor(type_declaration)),
        ));
    }
    issues
}
