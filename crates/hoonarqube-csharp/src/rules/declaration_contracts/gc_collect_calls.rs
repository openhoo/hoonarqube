use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S1215 — explicit `GC.Collect` calls fight the garbage
/// collector's own heuristics.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "GC", &["Collect"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S1215",
                "Remove this call to 'GC.Collect'.",
                range_of(access),
            )
        })
        .collect()
}
