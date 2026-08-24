use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of,
    simple_name,
};
use crate::rules::naming::type_members;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3925 — implementing `ISerializable` promises the
/// serialization constructor and a `GetObjectData` override; missing
/// either breaks deserialization.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for class_declaration in collect_kinds(root, &["class_declaration"]) {
        if is_error_tainted(class_declaration)
            || !base_simple_names(class_declaration, source).contains(&"ISerializable")
        {
            continue;
        }
        let members = type_members(class_declaration);
        let has_serialization_ctor = members.iter().any(|member| {
            member.kind() == "constructor_declaration"
                && parameters_of(*member).iter().any(|parameter| {
                    parameter
                        .child_by_field_name("type")
                        .is_some_and(|type_node| {
                            simple_name(node_text(type_node, source)) == "SerializationInfo"
                        })
                })
        });
        let has_get_object_data = members.iter().any(|member| {
            member.kind() == "method_declaration"
                && member
                    .child_by_field_name("name")
                    .is_some_and(|name| node_text(name, source) == "GetObjectData")
        });
        if !has_serialization_ctor || !has_get_object_data {
            issues.push(issue(
                language,
                "S3925",
                "Complete the 'ISerializable' implementation: add the serialization constructor and 'GetObjectData'.",
                range_of(name_anchor(class_declaration)),
            ));
        }
    }
    issues
}
