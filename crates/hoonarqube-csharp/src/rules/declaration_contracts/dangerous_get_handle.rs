use crate::CsLanguage;
use crate::cst::{issue, range_of};
use crate::rules::expressions::banned_member_accesses;
use hoonarqube_ir::Issue;
use tree_sitter::Node;

/// csharpsquid:S3869 — raw handle leaks defeat `SafeHandle`'s release safety.
pub(crate) fn check(root: Node<'_>, source: &str, language: CsLanguage) -> Vec<Issue> {
    banned_member_accesses(root, source, "SafeHandle", &["DangerousGetHandle"])
        .into_iter()
        .map(|access| {
            issue(
                language,
                "S3869",
                "Remove this 'DangerousGetHandle' call.",
                range_of(access),
            )
        })
        .collect()
}
