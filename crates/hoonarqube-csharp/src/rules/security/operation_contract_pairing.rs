use super::support::attributed_declaration;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::declaration_contracts::attribute_applications;
use crate::rules::expressions::enclosing_type;
use crate::rules::modifiers::has_any_attribute;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3597 — `[OperationContract]` methods belong to
/// `[ServiceContract]` types.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for (name, _, attribute) in attribute_applications(root, source) {
        if !matches!(name, "OperationContract" | "OperationContractAttribute") {
            continue;
        }
        let Some(method) = attributed_declaration(attribute) else {
            continue;
        };
        if method.kind() != "method_declaration" {
            continue;
        }
        let contracted = enclosing_type(method)
            .is_some_and(|ty| has_any_attribute(ty, source, &["ServiceContract"]));
        if !contracted {
            issues.push(issue(
                language,
                "S3597",
                "Use '[OperationContract]' only on methods of a '[ServiceContract]' type.",
                range_of(attribute),
            ));
        }
    }
    issues
}
