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
        for parameter in collect_kinds(list, &["type_parameter"]) {
            let name = node_text(parameter, source);
            if !used.contains(name) {
                issues.push(issue(
                    language,
                    "S4018",
                    format!("Type parameter \"{name}\" never appears in the parameter list."),
                    range_of(parameter, source),
                ));
            }
        }
    }
    issues
}
