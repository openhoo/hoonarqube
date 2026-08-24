use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S5773 — `TypeNameHandling` beyond `None` lets payloads name
/// arbitrary types to instantiate.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(
        root,
        source,
        "TypeNameHandling",
        &["All", "Auto", "Objects", "Arrays"],
    )
    .into_iter()
    .map(|access| {
        issue(
            language,
            "S5773",
            "Restrict deserialization by keeping 'TypeNameHandling' at 'None'.",
            range_of(access),
        )
    })
    .collect()
}
