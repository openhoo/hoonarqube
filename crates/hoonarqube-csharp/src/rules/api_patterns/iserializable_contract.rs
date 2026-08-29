use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, node_text,
    parameters_of, range_of, simple_name,
};
use crate::rules::modifiers::{has_any_attribute, has_modifier};
use crate::rules::naming::{has_explicit_interface_specifier, type_members};
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
        if !is_serializable_implementation(class_declaration, source) {
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
        let sealed = has_modifier(&class_modifiers, "sealed");
        let contract = SerializationContract {
            sealed,
            serializable: ContractState::from(serializable),
            serialization_ctor: ContractState::from(has_serialization_constructor(
                &members, source, sealed,
            )),
            extensible_method: ContractState::from(has_extensible_get_object_data(
                &members, source, sealed,
            )),
        };
        if contract.serializable.is_missing()
            || contract.serialization_ctor.is_missing()
            || contract.extensible_method.is_missing()
        {
            issues.push(issue(
                language,
                "S3925",
                serialization_message(class_name, contract),
                range_of(name_anchor(class_declaration), source),
            ));
        }
    }
    issues
}

fn is_serializable_implementation(class_declaration: Node<'_>, source: &str) -> bool {
    !is_error_tainted(class_declaration)
        && base_simple_names(class_declaration, source).contains(&"ISerializable")
}

fn has_serialization_constructor(members: &[Node<'_>], source: &str, sealed: bool) -> bool {
    members.iter().any(|member| {
        if member.kind() != "constructor_declaration"
            || !has_serialization_parameters(*member, source)
        {
            return false;
        }
        let modifiers = modifiers_of(*member, source);
        valid_constructor_access(&modifiers, sealed)
    })
}

fn valid_constructor_access(modifiers: &[&str], sealed: bool) -> bool {
    if sealed {
        has_modifier(modifiers, "private")
            || !modifiers
                .iter()
                .any(|modifier| matches!(*modifier, "public" | "protected" | "internal"))
    } else {
        has_modifier(modifiers, "protected")
            && !modifiers
                .iter()
                .any(|modifier| matches!(*modifier, "public" | "private" | "internal"))
    }
}

fn has_extensible_get_object_data(members: &[Node<'_>], source: &str, sealed: bool) -> bool {
    members
        .iter()
        .any(|member| valid_get_object_data(*member, source, sealed))
}

fn valid_get_object_data(member: Node<'_>, source: &str, sealed: bool) -> bool {
    if member.kind() != "method_declaration"
        || member
            .child_by_field_name("name")
            .is_none_or(|name| simple_name(node_text(name, source)) != "GetObjectData")
        || member
            .child_by_field_name("returns")
            .is_none_or(|returns| simple_name(node_text(returns, source)) != "void")
        || !has_serialization_parameters(member, source)
    {
        return false;
    }
    let modifiers = modifiers_of(member, source);
    explicitly_implements_iserializable(member, source)
        || (has_modifier(&modifiers, "public")
            && (sealed
                || has_modifier(&modifiers, "virtual")
                || has_modifier(&modifiers, "override")))
}

fn explicitly_implements_iserializable(member: Node<'_>, source: &str) -> bool {
    has_explicit_interface_specifier(member)
        && collect_kinds(member, &["explicit_interface_specifier"])
            .first()
            .is_some_and(|specifier| {
                simple_name(node_text(*specifier, source).trim_end_matches('.')) == "ISerializable"
            })
}

#[derive(Clone, Copy)]
struct SerializationContract {
    sealed: bool,
    serializable: ContractState,
    serialization_ctor: ContractState,
    extensible_method: ContractState,
}

#[derive(Clone, Copy)]
enum ContractState {
    Present,
    Missing,
}

impl ContractState {
    fn is_missing(self) -> bool {
        matches!(self, Self::Missing)
    }
}

impl From<bool> for ContractState {
    fn from(present: bool) -> Self {
        if present {
            Self::Present
        } else {
            Self::Missing
        }
    }
}

fn serialization_message(class_name: &str, contract: SerializationContract) -> String {
    let mut message = String::from(
        "Update this implementation of 'ISerializable' to conform to the recommended serialization pattern.",
    );
    if contract.serializable.is_missing() {
        let _ = write!(
            message,
            " Add 'System.SerializableAttribute' attribute on '{class_name}' because it implements 'ISerializable'."
        );
    }
    if contract.serialization_ctor.is_missing() {
        let accessibility = if contract.sealed {
            "private"
        } else {
            "protected"
        };
        let _ = write!(
            message,
            " Add a '{accessibility}' constructor '{class_name}(SerializationInfo, StreamingContext)'."
        );
    }
    if contract.extensible_method.is_missing() {
        let _ = write!(
            message,
            " Make 'GetObjectData' 'public' and 'virtual', or seal '{class_name}'."
        );
    }
    message
}

fn has_serialization_parameters(declaration: Node<'_>, source: &str) -> bool {
    let parameters = parameters_of(declaration);
    parameters.len() == 2
        && parameters
            .iter()
            .all(|parameter| modifiers_of(*parameter, source).is_empty())
        && parameters
            .iter()
            .filter_map(|parameter| parameter.child_by_field_name("type"))
            .map(|type_node| simple_name(node_text(type_node, source)))
            .eq(["SerializationInfo", "StreamingContext"])
}
