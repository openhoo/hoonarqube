use super::support::DISPOSABLE_TYPES;
use super::support::member_declared_type;
use crate::CsLanguage;
use crate::cst::{
    base_simple_names, collect_kinds, is_error_tainted, issue, modifiers_of, node_text, range_of,
    simple_name,
};
use crate::rules::modifiers::has_modifier;
use crate::rules::naming::type_members;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2931 — classes declaring disposable members without
/// implementing `IDisposable`. Subset: fields/properties typed by the
/// well-known disposable table (or `IDisposable` itself) on non-partial
/// classes whose base list lacks the interface textually; disposable bases
/// outside the file stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class| !is_error_tainted(*class))
        .filter(|class| !has_modifier(&modifiers_of(*class, source), "partial"))
        .filter(|class| {
            !base_simple_names(*class, source)
                .iter()
                .any(|name| *name == "IDisposable" || DISPOSABLE_TYPES.contains(name))
        })
        .filter(|class| {
            type_members(*class).into_iter().any(|member| {
                matches!(member.kind(), "field_declaration" | "property_declaration")
                    && member_declared_type(member).is_some_and(|type_node| {
                        let declared = simple_name(node_text(type_node, source));
                        declared == "IDisposable" || DISPOSABLE_TYPES.contains(&declared)
                    })
            })
        })
        .filter_map(|class| class.child_by_field_name("name"))
        .map(|name| {
            issue(
                language,
                "S2931",
                "Implement 'IDisposable' on this class; it declares disposable members.",
                range_of(name),
            )
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2931_disposable_properties_trigger_the_rule_too() {
        let report =
            analyze_default("class Cache\n{\n    public FileStream Stream { get; set; }\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S2931").len(), 1);
    }

    #[test]
    fn s2931_partial_classes_stay_uncovered() {
        let report = analyze_default("partial class Cache\n{\n    private FileStream stream;\n}\n");
        assert!(with_key(&report, "csharpsquid:S2931").is_empty());
    }

    #[test]
    fn s2931_disposable_bases_from_the_table_exempt_the_class() {
        let report =
            analyze_default("class Cache : MemoryStream\n{\n    private FileStream stream;\n}\n");
        assert!(with_key(&report, "csharpsquid:S2931").is_empty());
    }

    #[test]
    fn s2931_idisposable_typed_members_count() {
        let report = analyze_default("class Cache\n{\n    private IDisposable resource;\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S2931").len(), 1);
    }

    #[test]
    fn s2931_qualified_member_types_still_match_the_table() {
        let report =
            analyze_default("class Cache\n{\n    private System.IO.FileStream stream;\n}\n");
        assert_eq!(with_key(&report, "csharpsquid:S2931").len(), 1);
    }

    #[test]
    fn s2931_flags_each_offending_class_distinctly() {
        let report = analyze_default(
            "class First\n{\n    private FileStream stream;\n}\nclass Second\n{\n    private SqlConnection connection;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2931");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 5);
    }
}
