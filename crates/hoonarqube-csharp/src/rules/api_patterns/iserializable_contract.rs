use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, node_text, parameters_of, range_of,
    simple_name,
};
use crate::rules::modifiers::{has_any_attribute, has_modifier};
use crate::rules::naming::type_members;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use std::fmt::Write;
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
        let class_name = class_declaration
            .child_by_field_name("name")
            .map_or("type", |name| node_text(name, source));
        let class_modifiers = crate::cst::modifiers_of(class_declaration, source);
        let serializable = has_any_attribute(
            class_declaration,
            source,
            &["Serializable", "SerializableAttribute"],
        );
        let has_serialization_ctor = members.iter().any(|member| {
            member.kind() == "constructor_declaration" && {
                let parameter_types: Vec<&str> = parameters_of(*member)
                    .iter()
                    .filter_map(|parameter| parameter.child_by_field_name("type"))
                    .map(|type_node| simple_name(node_text(type_node, source)))
                    .collect();
                parameter_types == ["SerializationInfo", "StreamingContext"]
            }
        });
        let get_object_data = members.iter().find(|member| {
            member.kind() == "method_declaration"
                && member
                    .child_by_field_name("name")
                    .is_some_and(|name| node_text(name, source) == "GetObjectData")
        });
        let method_extensible = get_object_data.is_some_and(|method| {
            let modifiers = crate::cst::modifiers_of(*method, source);
            has_modifier(&modifiers, "public") && has_modifier(&modifiers, "virtual")
        }) || has_modifier(&class_modifiers, "sealed");
        if !serializable || !has_serialization_ctor || !method_extensible {
            let mut message = String::from(
                "Update this implementation of 'ISerializable' to conform to the recommended serialization pattern.",
            );
            if !serializable {
                let _ = write!(
                    message,
                    " Add 'System.SerializableAttribute' attribute on '{class_name}' because it implements 'ISerializable'."
                );
            }
            if !has_serialization_ctor {
                let _ = write!(
                    message,
                    " Add a 'protected' constructor '{class_name}(SerializationInfo, StreamingContext)'."
                );
            }
            if !method_extensible {
                let _ = write!(
                    message,
                    " Make 'GetObjectData' 'public' and 'virtual', or seal '{class_name}'."
                );
            }
            issues.push(issue(
                language,
                "S3925",
                message,
                range_of(name_anchor(class_declaration), source),
            ));
        }
    }
    issues
}
