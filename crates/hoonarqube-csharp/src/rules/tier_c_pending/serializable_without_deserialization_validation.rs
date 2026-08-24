use crate::CsLanguage;
use crate::cst::{base_simple_names, collect_kinds, is_error_tainted, issue, range_of};
use crate::rules::modifiers::has_any_attribute;
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5766 — serializable types without deserialization
/// validation. Subset: `[Serializable]` classes lacking an
/// `[OnDeserialized]`/`[OnDeserializing]` method and the
/// `IDeserializationCallback` interface; binary-formatter hardening outside
/// these hooks stays uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class| !is_error_tainted(*class))
        .filter(|class| {
            has_any_attribute(*class, source, &["Serializable", "SerializableAttribute"])
        })
        .filter(|class| {
            !base_simple_names(*class, source).contains(&"IDeserializationCallback")
        })
        .filter(|class| {
            !type_members(*class).into_iter().any(|member| {
                member.kind() == "method_declaration"
                    && has_any_attribute(
                        member,
                        source,
                        &[
                            "OnDeserialized",
                            "OnDeserializedAttribute",
                            "OnDeserializing",
                            "OnDeserializingAttribute",
                        ],
                    )
            })
        })
        .filter_map(|class| class.child_by_field_name("name"))
        .map(|name| {
            issue(
                language,
                "S5766",
                "Validate this type's data during deserialization, e.g. with an '[OnDeserialized]' method or 'IDeserializationCallback'.",
                range_of(name),
            )
        })
        .collect()
}
