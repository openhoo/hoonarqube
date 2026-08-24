use super::support::attributed_declaration;
use super::support::return_type_text;
use crate::CsLanguage;
use crate::cst::{issue, node_text, range_of};
use crate::rules::declaration_contracts::attribute_applications;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3598 — one-way operations cannot report a result.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, args, attribute) in attribute_applications(root, source) {
        if !matches!(name, "OperationContract" | "OperationContractAttribute") {
            continue;
        }
        let Some(args) = args else { continue };
        let args_text = node_text(args, source);
        if !(args_text.contains("IsOneWay") && args_text.contains("true")) {
            continue;
        }
        let Some(method) = attributed_declaration(attribute) else {
            continue;
        };
        if method.kind() == "method_declaration" && return_type_text(method, source) != "void" {
            issues.push(issue(
                language,
                "S3598",
                "Remove 'IsOneWay' from this operation or make it return void.",
                range_of(attribute),
            ));
        }
    }
    issues
}
