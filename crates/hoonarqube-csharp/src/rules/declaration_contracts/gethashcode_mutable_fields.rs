use crate::CsLanguage;
use crate::cst::{collect_kinds, issue, range_of};
use crate::rules::expressions::{
    member_named, mutable_field_names, overridden_names, references_identifier,
};
use crate::rules::naming::TYPE_DECLARATION_KINDS;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S2328 — mutable fields poison hash codes the moment someone
/// mutates them.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    let mut issues = Vec::new();
    for type_node in collect_kinds(root, &TYPE_DECLARATION_KINDS) {
        if !overridden_names(type_node, source).contains("GetHashCode") {
            continue;
        }
        let mutable_fields = mutable_field_names(type_node, source);
        if mutable_fields.is_empty() {
            continue;
        }
        if let Some(method) = member_named(type_node, "method_declaration", "GetHashCode", source) {
            let poisoned = mutable_fields
                .iter()
                .any(|field| references_identifier(method, field, source));
            if poisoned {
                issues.push(issue(
                    language,
                    "S2328",
                    "Reference only immutable fields from 'GetHashCode'.",
                    range_of(method),
                ));
            }
        }
    }
    issues
}
