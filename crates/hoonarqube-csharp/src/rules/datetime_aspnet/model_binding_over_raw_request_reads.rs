use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6932 — raw request reads bypass binding and validation;
/// model parameters document the contract.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "Request", &["Form", "Query", "Body"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S6932",
                "Bind this data through a model instead of reading the request.",
                range_of(access, source),
            )
        })
        .collect()
}
