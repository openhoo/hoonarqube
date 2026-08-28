use super::support::attributed_declaration;
use super::support::return_type_text;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::declaration_contracts::attribute_applications;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3603 — methods annotated '[Pure]' must return a value.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, _, attribute) in attribute_applications(root, source) {
        if !matches!(name, "Pure" | "PureAttribute") {
            continue;
        }
        let Some(method) = attributed_declaration(attribute) else {
            continue;
        };
        if method.kind() == "method_declaration" && return_type_text(method, source) == "void" {
            issues.push(issue(
                language,
                "S3603",
                "Remove the 'Pure' attribute or change the method to return a value.",
                range_of(attribute, source),
            ));
        }
    }
    issues
}
