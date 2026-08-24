use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3996 — URI-named properties should carry real URIs.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) {
            continue;
        }
        let named_uri = property
            .child_by_field_name("name")
            .and_then(|name| node_text(name, source).strip_suffix("Uri"))
            .is_some_and(|prefix| !prefix.is_empty());
        let typed_string = property
            .child_by_field_name("type")
            .is_some_and(|type_node| simple_name(node_text(type_node, source)) == "string");
        if named_uri && typed_string {
            issues.push(issue(
                language,
                "S3996",
                "Expose this URI-valued property as 'System.Uri'.",
                range_of(property),
            ));
        }
    }
    issues
}
