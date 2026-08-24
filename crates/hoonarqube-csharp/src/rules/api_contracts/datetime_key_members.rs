use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::expressions::first_named_child;
use crate::rules::logging::field_declarator_names;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3363 — date/time values make unstable, ambiguous keys.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    const DATETIME_TYPES: [&str; 2] = ["DateTime", "DateTimeOffset"];
    let mut issues = Vec::new();
    for property in collect_kinds(root, &["property_declaration"]) {
        if is_error_tainted(property) {
            continue;
        }
        let named_key = property
            .child_by_field_name("name")
            .is_some_and(|name| key_shaped(node_text(name, source)));
        let typed_datetime = property
            .child_by_field_name("type")
            .is_some_and(|type_node| {
                DATETIME_TYPES.contains(&simple_name(node_text(type_node, source)))
            });
        if named_key && typed_datetime {
            issues.push(issue(
                language,
                "S3363",
                "Do not use date/time types for this key member.",
                range_of(property),
            ));
        }
    }
    for field in collect_kinds(root, &["field_declaration"]) {
        if is_error_tainted(field) {
            continue;
        }
        let named_key = field_declarator_names(field, source)
            .into_iter()
            .any(key_shaped);
        let typed_datetime = collect_kinds(field, &["variable_declaration"])
            .first()
            .and_then(|declaration| first_named_child(*declaration))
            .is_some_and(|type_node| {
                DATETIME_TYPES.contains(&simple_name(node_text(type_node, source)))
            });
        if named_key && typed_datetime {
            issues.push(issue(
                language,
                "S3363",
                "Do not use date/time types for this key member.",
                range_of(field),
            ));
        }
    }
    issues
}

/// Key-shaped member names (`Id`, `OrderKey`, ...).
fn key_shaped(name: &str) -> bool {
    name == "Id"
        || name == "Key"
        || (name.ends_with("Id") && name.len() > 2)
        || (name.ends_with("Key") && name.len() > 3)
}
