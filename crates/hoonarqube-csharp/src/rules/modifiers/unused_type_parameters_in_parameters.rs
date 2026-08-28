use super::support::type_parameter_list_of;
use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S4018 — every method type parameter must appear in the
/// parameter list.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        let Some((list, _)) = type_parameter_list_of(method) else {
            continue;
        };
        let Some(parameters) = method.child_by_field_name("parameters") else {
            continue;
        };
        let used: std::collections::HashSet<&str> = collect_kinds(parameters, &["identifier"])
            .iter()
            .map(|identifier| node_text(*identifier, source))
            .collect();
        let has_unused = collect_kinds(list, &["type_parameter"])
            .into_iter()
            .any(|parameter| !used.contains(node_text(parameter, source)));
        if has_unused {
            let Some(name) = method.child_by_field_name("name") else {
                continue;
            };
            issues.push(issue(
                language,
                "S4018",
                "Refactor this method to use all type parameters in the parameter list to enable type inference.",
                range_of(name, source),
            ));
        }
    }
    issues
}
