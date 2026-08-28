use super::support::member_declared_type;
use super::support::normalized_type_name;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of, simple_name};
use crate::rules::modifiers::has_any_attribute;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6797 — `[SupplyParameterFromQuery]` properties whose type is
/// not bindable from a query string. Subset: a closed type-text table of the
/// supported primitives plus their nullable and array forms; every other
/// declared type is flagged.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["property_declaration"])
        .into_iter()
        .filter(|property| !is_error_tainted(*property))
        .filter(|property| {
            has_any_attribute(
                *property,
                source,
                &[
                    "SupplyParameterFromQuery",
                    "SupplyParameterFromQueryAttribute",
                ],
            )
        })
        .filter_map(|property| {
            member_declared_type(property).filter(|type_node| {
                !QUERY_PARAMETER_TYPES
                    .contains(&normalized_type_name(node_text(*type_node, source)))
            })
        })
        .map(|type_node| {
            issue(
                language,
                "S6797",
                format!(
                    "Query parameter type '{}' is not supported.",
                    simple_name(node_text(type_node, source))
                ),
                range_of(type_node, source),
            )
        })
        .collect()
}

/// Property types Blazor binds from query strings (plus their nullable and
/// array forms).
const QUERY_PARAMETER_TYPES: [&str; 12] = [
    "bool", "DateOnly", "DateTime", "TimeOnly", "decimal", "double", "float", "Guid", "int",
    "long", "short", "string",
];

#[cfg(test)]
mod tests {
    use crate::tests::{analyze_default, with_key};

    #[test]
    fn s6797_ignores_properties_without_the_query_attribute() {
        let report =
            analyze_default("class Filters\n{\n    public List<int> Pages { get; set; }\n}\n");
        assert!(with_key(&report, "csharpsquid:S6797").is_empty());
    }

    #[test]
    fn s6797_accepts_supported_nullable_array_and_qualified_forms() {
        let report = analyze_default(
            "class Filters\n{\n    [SupplyParameterFromQuery]\n    public int Count { get; set; }\n    [SupplyParameterFromQuery]\n    public Guid? Row { get; set; }\n    [SupplyParameterFromQuery]\n    public decimal[] Amounts { get; set; }\n    [SupplyParameterFromQuery]\n    public System.DateTime When { get; set; }\n}\n",
        );
        assert!(with_key(&report, "csharpsquid:S6797").is_empty());
    }

    #[test]
    fn s6797_flags_each_unsupported_property_at_its_own_line() {
        let report = analyze_default(
            "class Filters\n{\n    [SupplyParameterFromQuery]\n    public List<int> Pages { get; set; }\n    [SupplyParameterFromQuery]\n    public Dictionary<string, int> Map { get; set; }\n}\n",
        );
        let flagged = with_key(&report, "csharpsquid:S6797");
        assert_eq!(flagged.len(), 2);
        assert_eq!(flagged[0].range.start.line, 4);
        assert_eq!(flagged[1].range.start.line, 6);
    }

    #[test]
    fn s6797_attribute_long_spelling_still_gates_the_check() {
        let report = analyze_default(
            "class Filters\n{\n    [SupplyParameterFromQueryAttribute]\n    public List<int> Pages { get; set; }\n}\n",
        );
        assert_eq!(with_key(&report, "csharpsquid:S6797").len(), 1);
    }
}
