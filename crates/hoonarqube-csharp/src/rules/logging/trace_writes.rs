use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S6670 — `Trace` output bypasses sinks, levels, correlation.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "Trace", &["Write", "WriteLine"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S6670",
                "Replace this 'Trace' output with proper logging.",
                range_of(access),
            )
        })
        .collect()
}
