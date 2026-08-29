use super::support::{collect_kinds_in_callable, local_now_stores};
use crate::CsLanguage;
use crate::cst::{ancestors_of, issue, node_text, parameters_of, range_of, simple_name};
use crate::rules::dataflow::callable_blocks;
use crate::rules::naming::{TYPE_DECLARATION_KINDS, type_members};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6566 — `DateTimeOffset` targets must not be filled from
/// bare `DateTime` values, which carry no offset and silently adopt the
/// machine zone. Bound: same-type fields/properties and callable-local
/// declarations.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for body in callable_blocks(root) {
        let offsets = datetimeoffset_target_names(body, source);
        for (name, store) in local_now_stores(body, source) {
            if offsets.contains(name) {
                let anchor = collect_kinds_in_callable(store, &["identifier"])
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

/// Fields, properties, locals, and parameters visible to one callable and
/// typed exactly `DateTimeOffset` (optionally nullable or qualified).
fn datetimeoffset_target_names(body: Node<'_>, source: &str) -> std::collections::HashSet<String> {
    let mut names = std::collections::HashSet::new();
    names.extend(local_offset_names(body, source));
    names.extend(parameter_offset_names(body, source));
    names.extend(member_offset_names(body, source));
    names
}

fn local_offset_names(body: Node<'_>, source: &str) -> Vec<String> {
    collect_kinds_in_callable(body, &["variable_declaration"])
        .into_iter()
        .filter(|declaration| declaration_is_datetimeoffset(*declaration, source))
        .flat_map(|declaration| declarator_names(declaration, source))
        .collect()
}

fn parameter_offset_names(body: Node<'_>, source: &str) -> Vec<String> {
    body.parent()
        .into_iter()
        .flat_map(parameters_of)
        .filter(|parameter| declaration_is_datetimeoffset(*parameter, source))
        .filter_map(|parameter| parameter.child_by_field_name("name"))
        .map(|name| node_text(name, source).to_owned())
        .collect()
}

fn member_offset_names(body: Node<'_>, source: &str) -> Vec<String> {
    let Some(type_node) =
        ancestors_of(body).find(|ancestor| TYPE_DECLARATION_KINDS.contains(&ancestor.kind()))
    else {
        return Vec::new();
    };
    type_members(type_node)
        .into_iter()
        .flat_map(|member| offset_member_names(member, source))
        .collect()
}

fn offset_member_names(member: Node<'_>, source: &str) -> Vec<String> {
    if member.kind() == "field_declaration" {
        return collect_kinds_in_callable(member, &["variable_declaration"])
            .into_iter()
            .next()
            .filter(|declaration| declaration_is_datetimeoffset(*declaration, source))
            .map_or_else(Vec::new, |declaration| {
                declarator_names(declaration, source)
            });
    }
    if member.kind() == "property_declaration" && declaration_is_datetimeoffset(member, source) {
        return member
            .child_by_field_name("name")
            .map(|name| vec![node_text(name, source).to_owned()])
            .unwrap_or_default();
    }
    Vec::new()
}

fn declaration_is_datetimeoffset(declaration: Node<'_>, source: &str) -> bool {
    declaration
        .child_by_field_name("type")
        .is_some_and(|type_node| is_datetimeoffset(type_node, source))
}

fn declarator_names(declaration: Node<'_>, source: &str) -> Vec<String> {
    collect_kinds_in_callable(declaration, &["variable_declarator"])
        .into_iter()
        .filter_map(|declarator| declarator.child_by_field_name("name"))
        .map(|name| node_text(name, source).to_owned())
        .collect()
}

fn is_datetimeoffset(type_node: Node<'_>, source: &str) -> bool {
    let text = node_text(type_node, source).trim_end_matches('?');
    simple_name(text) == "DateTimeOffset"
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6566_keeps_same_named_locals_in_separate_methods() {
        let report = analyze_default(
            "class C\n{\n    void Offset()\n    {\n        DateTimeOffset created = DateTimeOffset.Now;\n    }\n\n    void Local()\n    {\n        DateTime created = DateTime.Now;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6566").is_empty());
    }

    #[test]
    fn s6566_reports_nested_local_function_once() {
        let report = analyze_default(
            "class C\n{\n    void Outer()\n    {\n        void Local()\n        {\n            DateTimeOffset created = DateTime.Now;\n        }\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6566").len(), 1);
    }

    #[test]
    fn s6566_does_not_treat_prefix_types_as_datetimeoffset() {
        let report = analyze_default(
            "class C\n{\n    void M()\n    {\n        DateTimeOffsetFactory created = DateTime.Now;\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6566").is_empty());
    }

    #[test]
    fn s6566_tracks_datetimeoffset_fields_and_properties() {
        let report = analyze_default(
            "class C\n{\n    DateTimeOffset created;\n    DateTimeOffset Modified { get; set; }\n\n    void M()\n    {\n        created = DateTime.Now;\n        Modified = DateTime.Now;\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6566").len(), 2);
    }
}
