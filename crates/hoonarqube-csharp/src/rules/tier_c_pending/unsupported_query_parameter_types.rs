use super::support::member_declared_type;
use super::support::normalized_type_name;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
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
        .filter(|property| {
            member_declared_type(*property).is_some_and(|type_node| {
                !QUERY_PARAMETER_TYPES.contains(&normalized_type_name(node_text(type_node, source)))
            })
        })
        .filter_map(|property| property.child_by_field_name("name"))
        .map(|name| {
            issue(
                language,
                "S6797",
                "Use a supported primitive, its nullable form, or an array of those for this query parameter.",
                range_of(name),
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
