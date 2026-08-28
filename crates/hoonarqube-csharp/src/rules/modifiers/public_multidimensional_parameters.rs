use super::support::has_modifier;
use super::support::is_multidimensional_array;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, modifiers_of, parameters_of, range_of};
use crate::rules::expressions::enclosing_type;
use crate::rules::modifiers::type_declared_rank;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2368 — public methods must not surface multi-dimensional
/// array parameters.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if !has_modifier(&modifiers_of(method, source), "public")
            || enclosing_type(method)
                .is_none_or(|type_node| type_declared_rank(type_node, source) != 6)
        {
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
            "Make this method private or simplify its parameters to not use multidimensional/jagged arrays.",
            range_of(name, source),
        ));
    }
    issues
}
