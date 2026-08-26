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
                range_of(name, source),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s5766_flags_each_unvalidated_serializable_class() {
        let report = analyze_default(
            "[Serializable]\nclass First\n{\n}\n[Serializable]\nclass Second\n{\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S5766");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 2);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s5766_on_deserializing_hook_counts_as_validation() {
        let report = analyze_default(
            "[Serializable]\nclass Session\n{\n    [OnDeserializing]\n    void Before(StreamingContext context)\n    {\n    }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S5766").is_empty());
    }

    #[test]
    fn s5766_serializable_attribute_long_spelling_still_flags() {
        let report = analyze_default("[SerializableAttribute]\nclass Session\n{\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S5766").len(), 1);
    }

    #[test]
    fn s5766_unrelated_method_attributes_do_not_validate() {
        let report = analyze_default(
            "[Serializable]\nclass Session\n{\n    [Obsolete]\n    void Refresh()\n    {\n    }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S5766").len(), 1);
    }

    #[test]
    fn s5766_classes_without_the_attribute_stay_clean() {
        let report = analyze_default("class Session\n{\n}\n");
        assert!(with_key(&report, "csharpsquid:S5766").is_empty());
    }
}
