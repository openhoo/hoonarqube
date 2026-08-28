use crate::CsLanguage;
use crate::cst::{
    attributes_of, base_simple_names, collect_kinds, is_error_tainted, issue, node_text,
    parameters_of, range_of, simple_name,
};
use crate::rules::expressions::member_declarations_of_kind;
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use crate::rules::type_members::assembly_attribute_names;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4212 — serialization constructors need the same security
/// demand as ordinary constructors in partially trusted assemblies.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    if !assembly_attribute_names(root, source).iter().any(|name| {
        matches!(
            *name,
            "AllowPartiallyTrustedCallers" | "AllowPartiallyTrustedCallersAttribute"
        )
    }) {
        return Vec::new();
    }

    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if is_error_tainted(type_node)
            || !base_simple_names(type_node, source).contains(&"ISerializable")
        {
            continue;
        }
        let constructors = member_declarations_of_kind(type_node, "constructor_declaration");
        let has_secured_regular_constructor = constructors.iter().any(|constructor| {
            !is_serialization_constructor(*constructor, source)
                && has_security_demand(*constructor, source)
        });
        if !has_secured_regular_constructor {
            continue;
        }

        for constructor in constructors {
            if is_serialization_constructor(constructor, source)
                && !has_security_demand(constructor, source)
            {
                let anchor = constructor
                    .child_by_field_name("name")
                    .unwrap_or(constructor);
                issues.push(issue(
                    language,
                    "S4212",
                    "Secure this serialization constructor.",
                    range_of(anchor, source),
                ));
            }
        }
    }
    issues
}

fn is_serialization_constructor(constructor: Node<'_>, source: &str) -> bool {
    let param_types: Vec<&str> = parameters_of(constructor)
        .into_iter()
        .filter_map(|parameter| parameter.child_by_field_name("type"))
        .map(|ty| simple_name(node_text(ty, source)))
        .collect();
    ["SerializationInfo", "StreamingContext"]
        .iter()
        .all(|wanted| param_types.contains(wanted))
}

fn has_security_demand(constructor: Node<'_>, source: &str) -> bool {
    attributes_of(constructor, source).iter().any(|name| {
        matches!(
            *name,
            "FileIOPermission"
                | "SecurityPermission"
                | "PrincipalPermission"
                | "PermissionSet"
                | "EnvironmentPermission"
                | "RegistryPermission"
        )
    })
}
