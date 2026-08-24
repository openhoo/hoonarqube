use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3889 — suspended threads hold locks and never resume on
/// their own.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "Thread", &["Suspend", "Resume"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S3889",
                "Do not suspend or resume threads.",
                range_of(access),
            )
        })
        .collect()
}
