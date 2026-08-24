use super::support::has_modifier;
use super::support::is_multidimensional_array;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, parameters_of, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2368 — public methods must not surface multi-dimensional
/// array parameters.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !has_modifier(&modifiers_of(method, source), "public") {
            continue;
        }
        let offending = parameters_of(method).into_iter().any(|parameter| {
            parameter
                .child_by_field_name("type")
                .is_some_and(|type_node| {
                    collect_kinds(type_node, &["array_type"])
                        .iter()
                        .any(|array| is_multidimensional_array(*array, source))
                })
        });
        if !offending {
            continue;
        }
        let Some(name) = method.child_by_field_name("name") else {
            continue;
        };
        issues.push(issue(
            language,
            "S2368",
            "Remove this multi-dimensional array parameter from the public signature.",
            range_of(name),
        ));
    }
    issues
}
