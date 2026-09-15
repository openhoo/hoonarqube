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

/// csharpsquid:S2931 — classes owning disposable fields without
/// implementing `IDisposable`. Subset: non-readonly fields typed by the
/// well-known disposable table (or `IDisposable` itself) on non-partial
/// classes whose base list lacks the interface textually; disposable bases
/// outside the file stay uncovered. Ownership does not depend on initialization: the
/// dapper oracle reports `BenchmarkBase._connection` and
/// `HandCodedBenchmarks._postCommand`/`_table`, all assigned outside their
/// declarations, and names every offending field in the message.
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
        .filter_map(|class| {
            let owned_names = owned_disposable_field_names(class, source);
            if owned_names.is_empty() {
                return None;
            }
            Some((class.child_by_field_name("name")?, owned_names))
        })
        .map(|(name, owned_names)| {
            issue(
                language,
                "S2931",
                format!(
                    "Implement 'IDisposable' in this class and use the 'Dispose' method to call 'Dispose' on {}.",
                    join_field_names(&owned_names)
                ),
                range_of(name, source),
            )
        })
        .collect()
}

/// Every field-declarator name of `class` whose declared type is
/// `IDisposable` or a tabled disposable type, in declaration order.
fn owned_disposable_field_names<'t>(class: Node<'t>, source: &'t str) -> Vec<&'t str> {
    type_members(class)
        .into_iter()
        .filter(|member| member.kind() == "field_declaration")
        // Readonly fields are injected at construction rather than owned
        // across the instance lifetime: dapper's TableValuedParameter.table
        // (readonly DataTable) stays unreported while the assigned
        // SqlConnection/_postCommand/_table fields are reported.
        .filter(|member| !has_modifier(&modifiers_of(*member, source), "readonly"))
        .filter(|member| {
            member_declared_type(*member).is_some_and(|type_node| {
                let declared = simple_name(node_text(type_node, source));
                declared == "IDisposable" || DISPOSABLE_TYPES.contains(&declared)
            })
        })
        .flat_map(|field| collect_kinds(field, &["variable_declarator"]))
        .filter_map(|declarator| {
            declarator
                .child_by_field_name("name")
                .map(|name| node_text(name, source))
        })
        .collect()
}

/// The reference joins two offending fields with a plain `and`
/// (`'_postCommand' and '_table'`); longer lists use the same shape.
fn join_field_names(names: &[&str]) -> String {
    if let [single] = names {
        return format!("'{single}'");
    }
    let head = names[..names.len() - 1]
        .iter()
        .map(|name| format!("'{name}'"))
        .collect::<Vec<_>>()
        .join(", ");
    format!("{head} and '{}'", names[names.len() - 1])
}

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s2931_observed_disposable_properties_are_not_owned() {
        let report =
            analyze_default("class Cache\n{\n    public FileStream Stream { get; set; }\n}\n");
        assert!(with_key(&report, "csharpsquid:S2931").is_empty());
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

    /// Ownership does not depend on initialization: dapper's
    /// `BenchmarkBase._connection` is assigned in `BaseSetup`, not at the
    /// declaration, and the reference still reports the class.
    #[test]
    fn s2931_uninitialized_idisposable_members_are_still_owned() {
        let report = analyze_default("class Cache\n{\n    private IDisposable resource;\n}\n");
        let flagged = with_key(&report, "csharpsquid:S2931");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Implement 'IDisposable' in this class and use the 'Dispose' method to call 'Dispose' on 'resource'."
        );
    }

    /// dapper Dapper/TableValuedParameter.cs: the readonly ctor-injected
    /// `DataTable table` stays unreported by the reference.
    #[test]
    fn s2931_readonly_injected_fields_stay_clear() {
        let report = analyze_default(
            "using System.Data;\ninternal sealed class TableValuedParameter\n{\n    private readonly DataTable table;\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S2931").is_empty());
    }

    /// dapper Benchmarks.HandCoded.cs: `_postCommand` (`SqlCommand`) and
    /// `_table` (`DataTable`) are both disposable and named together.
    #[test]
    fn s2931_names_every_offending_field_together() {
        let report = analyze_default(
            "class HandCoded\n{\n    private SqlCommand _postCommand;\n    private DataTable _table;\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2931");
        assert_eq!(flagged.len(), 1);
        assert_eq!(
            flagged[0].message,
            "Implement 'IDisposable' in this class and use the 'Dispose' method to call 'Dispose' on '_postCommand' and '_table'."
        );
    }

    #[test]
    fn s2931_qualified_member_types_still_match_the_table() {
        let report = analyze_default(
            "class Cache\n{\n    private System.IO.FileStream stream = new System.IO.FileStream();\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S2931").len(), 1);
    }

    #[test]
    fn s2931_flags_each_offending_class_distinctly() {
        let report = analyze_default(
            "class First\n{\n    private FileStream stream = new FileStream();\n}\nclass Second\n{\n    private SqlConnection connection = new SqlConnection();\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S2931");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 1);
        assert_eq!(flagged[1].range.start.line, 5);
    }
}
