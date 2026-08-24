use crate::CsLanguage;
use crate::cst::{
    collect_kinds, is_error_tainted, issue, modifiers_of, node_text, parameters_of, range_of,
    simple_name,
};
use crate::rules::structure::name_anchor;
use crate::symbol_table::has_contract_modifier;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3997 — string overloads beside Uri overloads delegate to
/// the Uri version instead of re-implementing it.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut groups: std::collections::HashMap<&str, Vec<Node>> = std::collections::HashMap::new();
    for method in collect_kinds(root, &["method_declaration"]) {
        if is_error_tainted(method) {
            continue;
        }
        if let Some(name) = method.child_by_field_name("name") {
            groups
                .entry(node_text(name, source))
                .or_default()
                .push(method);
        }
    }
    let mut issues = Vec::new();
    for (name, methods) in groups {
        if methods.len() < 2 {
            continue;
        }
        let takes_uri = |method: Node| {
            parameters_of(method).iter().any(|parameter| {
                parameter
                    .child_by_field_name("type")
                    .is_some_and(|type_node| simple_name(node_text(type_node, source)) == "Uri")
            })
        };
        if !methods.iter().copied().any(takes_uri) {
            continue;
        }
        for method in methods {
            if takes_uri(method)
                || has_contract_modifier(&modifiers_of(method, source))
                || collect_kinds(method, &["object_creation_expression"])
                    .into_iter()
                    .any(|creation| {
                        creation
                            .child_by_field_name("type")
                            .is_some_and(|type_node| {
                                simple_name(node_text(type_node, source)) == "Uri"
                            })
                    })
            {
                continue;
            }
            issues.push(issue(
                language,
                "S3997",
                format!("Delegate this string-based '{name}' overload to the Uri overload."),
                range_of(name_anchor(method)),
            ));
        }
    }
    issues
}
