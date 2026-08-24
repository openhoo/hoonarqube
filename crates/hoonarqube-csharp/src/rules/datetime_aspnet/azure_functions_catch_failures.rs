use super::support::azure_function_methods;
use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::modifiers::subtree_contains_kind;
use crate::rules::structure::{body_of, name_anchor};
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6421 — unhandled exceptions in a Function surface as raw
/// 500s; failures belong in a try/catch.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    azure_function_methods(root, source)
        .into_iter()
        .filter(|method| body_of(*method).is_some_and(|body| body.kind() == "block"))
        .filter(|method| {
            !subtree_contains_kind(body_of(*method).unwrap_or(*method), "try_statement")
        })
        .map(|method| {
            issue(
                language,
                "S6421",
                "Wrap this Function in a try/catch and report the failure.",
                range_of(name_anchor(method)),
            )
        })
        .collect()
}
