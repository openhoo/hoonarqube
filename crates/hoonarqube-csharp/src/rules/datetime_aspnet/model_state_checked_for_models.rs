use super::support::controller_actions;
use super::support::is_api_controller_like;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, parameters_of, range_of};
use crate::rules::structure::{body_of, name_anchor};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6967 — actions receiving models must gate their use behind
/// 'ModelState.IsValid'.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    collect_kinds(root, &["class_declaration"])
        .into_iter()
        .filter(|class_node| is_api_controller_like(*class_node, source))
        .flat_map(|class_node| controller_actions(class_node, source))
        .filter(|action| {
            parameters_of(*action).iter().any(|parameter| {
                parameter
                    .child_by_field_name("type")
                    .is_some_and(|ty| !is_simple_binding_type(node_text(ty, source)))
            })
        })
        .filter(|action| {
            body_of(*action)
                .is_none_or(|body| !node_text(body, source).contains("ModelState.IsValid"))
        })
        .map(|action| {
            issue(
                language,
                "S6967",
                "Check 'ModelState.IsValid' before using bound model data.",
                range_of(name_anchor(action), source),
            )
        })
        .collect()
}

/// Simple types a binder handles without a complex model.
fn is_simple_binding_type(type_text: &str) -> bool {
    const SIMPLE_TYPES: [&str; 18] = [
        "bool",
        "byte",
        "sbyte",
        "char",
        "short",
        "ushort",
        "int",
        "uint",
        "long",
        "ulong",
        "float",
        "double",
        "decimal",
        "string",
        "Guid",
        "DateTime",
        "DateTimeOffset",
        "CancellationToken",
    ];
    SIMPLE_TYPES.contains(&type_text.trim_end_matches('?').trim_end_matches("[]"))
}
