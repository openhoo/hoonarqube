use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4057 — newly created `DataTable` and `DataSet` values need an
/// explicit locale.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["object_creation_expression"])
        .into_iter()
        .filter(|creation| !is_error_tainted(*creation))
        .filter(|creation| {
            creation
                .child_by_field_name("type")
                .is_some_and(|creation_type| {
                    matches!(
                        simple_name(node_text(creation_type, source)),
                        "DataTable" | "DataSet"
                    )
                })
        })
        .map(|creation| {
            let kind = creation
                .child_by_field_name("type")
                .map_or("data object", |creation_type| {
                    simple_name(node_text(creation_type, source))
                });
            issue(
                language,
                "S4057",
                format!("Set the locale for this '{kind}'."),
                range_of(creation, source),
            )
        })
        .collect()
}
