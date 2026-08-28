use super::support::attributed_declaration;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::declaration_contracts::attribute_applications;
use crate::rules::expressions::enclosing_type;
use crate::rules::modifiers::has_any_attribute;
use crate::rules::structure::name_anchor;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3597 — `[OperationContract]` methods belong to
/// `[ServiceContract]` types.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut missing_contract_types = Vec::new();
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
        if !contracted
            && let Some(type_node) = enclosing_type(method)
            && !missing_contract_types
                .iter()
                .any(|existing: &Node<'_>| existing.id() == type_node.id())
        {
            missing_contract_types.push(type_node);
        }
    }
    missing_contract_types
        .into_iter()
        .map(|type_node| {
            issue(
                language,
                "S3597",
                "Add the 'ServiceContract' attribute to  this class.",
                range_of(name_anchor(type_node), source),
            )
        })
        .collect()
}
