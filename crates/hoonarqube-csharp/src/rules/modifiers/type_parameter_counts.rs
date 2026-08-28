use super::support::type_parameter_list_of;
use crate::cst::{collect_kinds, issue, node_text, range_of};
use crate::rules::expressions::enclosing_type;
use crate::{AnalyzerOptions, CsLanguage};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2436 — generic arity is capped per type (`max`) and per
/// method (`maxMethod`).
pub(crate) fn check(
    root: Node<'_>,
    source: &str,
    language: CsLanguage,
    options: &AnalyzerOptions,
) -> Vec<Issue> {
    const TYPE_KINDS: [&str; 5] = [
        "class_declaration",
        "struct_declaration",
        "interface_declaration",
        "record_declaration",
        "delegate_declaration",
    ];
    let mut issues = Vec::new();
    for declaration in collect_kinds(root, &TYPE_KINDS) {
        if let Some((_, count)) = type_parameter_list_of(declaration) {
            let cap = options.maximum_generic_parameters_for_types;
            if count > cap {
                let Some(name) = declaration.child_by_field_name("name") else {
                    continue;
                };
                let type_name = node_text(name, source);
                issues.push(issue(
                    language,
                    "S2436",
                    format!(
                        "Reduce the number of generic parameters in the '{type_name}' class to no more than the {cap} authorized."
                    ),
                    range_of(name, source),
                ));
            }
        }
    }
    for method in collect_kinds(root, &["method_declaration"]) {
        if let Some((_, count)) = type_parameter_list_of(method) {
            let cap = options.maximum_generic_parameters_for_methods;
            if count > cap {
                let Some(name) = method.child_by_field_name("name") else {
                    continue;
                };
                let method_name = node_text(name, source);
                let qualified_name = enclosing_type(method)
                    .and_then(|type_node| type_node.child_by_field_name("name"))
                    .map_or_else(
                        || method_name.to_owned(),
                        |type_name| format!("{}.{method_name}", node_text(type_name, source)),
                    );
                issues.push(issue(
                    language,
                    "S2436",
                    format!(
                        "Reduce the number of generic parameters in the '{qualified_name}' method to no more than the {cap} authorized."
                    ),
                    range_of(name, source),
                ));
            }
        }
    }
    issues
}
