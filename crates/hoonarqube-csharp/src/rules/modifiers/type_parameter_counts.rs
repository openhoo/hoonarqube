use super::support::type_parameter_list_of;
use crate::cst::{collect_kinds, issue, range_of};
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
        if let Some((list, count)) = type_parameter_list_of(declaration) {
            let cap = options.maximum_generic_parameters_for_types;
            if count > cap {
                issues.push(issue(
                    language,
                    "S2436",
                    format!("Reduce the number of type parameters ({count} > {cap})."),
                    range_of(list, source),
                ));
            }
        }
    }
    for method in collect_kinds(root, &["method_declaration"]) {
        if let Some((list, count)) = type_parameter_list_of(method) {
            let cap = options.maximum_generic_parameters_for_methods;
            if count > cap {
                issues.push(issue(
                    language,
                    "S2436",
                    format!("Reduce the number of type parameters ({count} > {cap})."),
                    range_of(list, source),
                ));
            }
        }
    }
    issues
}
