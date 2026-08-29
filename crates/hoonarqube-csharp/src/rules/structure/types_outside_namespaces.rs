use super::support::name_anchor;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3903 — every top-level type lives in a named namespace.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    if collect_kinds(root, &["file_scoped_namespace_declaration"])
        .into_iter()
        .any(|declaration| declaration.parent() == Some(root))
    {
        return Vec::new();
    }
    let file_scope_types: Vec<Node> = collect_kinds(root, &TYPE_DECLARATION_KINDS)
        .into_iter()
        .filter(|type_declaration| {
            type_declaration
                .parent()
                .is_some_and(|parent| parent.kind() == "compilation_unit")
        })
        .collect();
    let mut issues = Vec::new();
    for type_declaration in file_scope_types {
        let name = name_anchor(type_declaration);
        issues.push(issue(
            language,
            "S3903",
            format!(
                "Move '{}' into a named namespace.",
                crate::cst::node_text(name, source)
            ),
            range_of(name, source),
        ));
    }
    issues
}
