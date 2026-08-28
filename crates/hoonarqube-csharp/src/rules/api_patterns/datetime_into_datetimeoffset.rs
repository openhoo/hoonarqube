use super::support::local_now_stores;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::dataflow::callable_blocks;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6566 — `DateTimeOffset` targets must not be filled from
/// bare `DateTime` values, which carry no offset and silently adopt the
/// machine zone. Bound: same-file `DateTimeOffset` declarations.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let offsets = datetimeoffset_target_names(root, source);
    if offsets.is_empty() {
        return Vec::new();
    }
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        for (name, store) in local_now_stores(body, source) {
            if offsets.contains(name) {
                let anchor = collect_kinds(store, &["identifier"])
                    .into_iter()
                    .find(|identifier| node_text(*identifier, source) == "DateTime")
                    .unwrap_or(store);
                issues.push(issue(
                    language,
                    "S6566",
                    "Prefer using \"DateTimeOffset\" instead of \"DateTime\"",
                    range_of(anchor, source),
                ));
            }
        }
    }
    issues
}

/// Fields, properties, locals, and parameters typed `DateTimeOffset…`.
fn datetimeoffset_target_names(root: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    let push_offset_declarators =
        |declaration: Node<'_>, names: &mut std::collections::HashSet<String>| {
            for declarator in collect_kinds(declaration, &["variable_declarator"]) {
                if let Some(name) = declarator.child_by_field_name("name") {
                    names.insert(node_text(name, source).to_owned());
                }
            }
        };
    for declaration in collect_kinds(root, &["field_declaration", "variable_declaration"]) {
        if declaration
            .child_by_field_name("type")
            .is_some_and(|type_node| node_text(type_node, source).starts_with("DateTimeOffset"))
        {
            push_offset_declarators(declaration, &mut names);
        }
    }
    for property in collect_kinds(root, &["property_declaration"]) {
        if property
            .child_by_field_name("type")
            .is_some_and(|type_node| node_text(type_node, source).starts_with("DateTimeOffset"))
            && let Some(name) = property.child_by_field_name("name")
        {
            names.insert(node_text(name, source).to_owned());
        }
    }
    for parameter in collect_kinds(root, &["parameter"]) {
        if let Some(type_node) = parameter.child_by_field_name("type")
            && node_text(type_node, source).starts_with("DateTimeOffset")
            && let Some(name) = parameter.child_by_field_name("name")
        {
            names.insert(node_text(name, source).to_owned());
        }
    }
    names
}
