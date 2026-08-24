use super::support::member_declared_type;
use super::support::normalized_type_name;
use crate::CsLanguage;
use crate::cst::{collect_kinds, is_error_tainted, issue, node_text, range_of};
use crate::rules::modifiers::has_any_attribute;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6800 — component parameters whose declared type contradicts
/// the route constraint on the same-named token. Subset: `[Parameter]`
/// properties matched case-insensitively against `{name:constraint}` tokens
/// of in-file template literals, with a table of constraint-accepted types;
/// unconstrained tokens and cross-file routes stay uncovered.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let tokens = collect_kinds(root, &["string_literal"])
        .into_iter()
        .filter(|literal| !is_error_tainted(*literal))
        .flat_map(|literal| route_tokens(node_text(literal, source)))
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return Vec::new();
    }
    collect_kinds(root, &["property_declaration"])
        .into_iter()
        .filter(|property| !is_error_tainted(*property))
        .filter(|property| {
            has_any_attribute(*property, source, &["Parameter", "ParameterAttribute"])
        })
        .filter_map(|property| {
            let name_node = property.child_by_field_name("name")?;
            let declared = member_declared_type(property)
                .map(|type_node| normalized_type_name(node_text(type_node, source)))?;
            tokens
                .iter()
                .any(|(token, constraint)| {
                    token.eq_ignore_ascii_case(node_text(name_node, source))
                        && route_constraint_allowed_types(constraint)
                            .is_some_and(|allowed| !allowed.contains(&declared))
                })
                .then_some(name_node)
        })
        .map(|name| {
            issue(
                language,
                "S6800",
                "Change this parameter's type so it matches the route constraint.",
                range_of(name),
            )
        })
        .collect()
}

/// Blazor route constraint → parameter type spellings it accepts.
fn route_constraint_allowed_types(constraint: &str) -> Option<&'static [&'static str]> {
    match constraint {
        "bool" => Some(&["bool"]),
        "datetime" => Some(&["DateTime"]),
        "decimal" => Some(&["decimal"]),
        "double" => Some(&["double"]),
        "float" => Some(&["float"]),
        "guid" => Some(&["Guid"]),
        "int" => Some(&["int"]),
        "long" => Some(&["long"]),
        _ => None,
    }
}

/// `(name, constraint)` pairs of `{name:constraint}` route tokens in one
/// template literal.
fn route_tokens(template: &str) -> Vec<(&str, &str)> {
    let mut tokens = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        let Some(close) = rest[open..].find('}') else {
            break;
        };
        if let Some((name, constraint)) = rest[open + 1..open + close].split_once(':') {
            tokens.push((name, constraint));
        }
        rest = &rest[open + close + 1..];
    }
    tokens
}
